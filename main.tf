terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 2.26"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_subscription" "primary" {
}

data "azurerm_client_config" "current" {
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "group_name" {
  type    = string
  default = "ace-vault"
}

resource "azurerm_resource_group" "rg" {
  name     = var.group_name
  location = var.location
}

resource "azurerm_resource_group" "image" {
  name     = "${var.group_name}-image"
  location = var.location
}

resource "azurerm_resource_group" "pkr" {
  name     = "${var.group_name}-image-pkr"
  location = var.location
}

resource "azurerm_storage_account" "vhds" {
  name                     = "acepackervhds"
  resource_group_name      = azurerm_resource_group.image.name
  location                 = azurerm_resource_group.image.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
}

resource "azurerm_user_assigned_identity" "msi" {
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  name                = "vault-identity"
}

resource "azurerm_role_definition" "vault-reader" {
  name        = "vault-reader"
  scope       = azurerm_resource_group.rg.id
  description = "Custom role with VM reader"

  permissions {
    actions     = [
      "Microsoft.Compute/virtualMachines/*/read",
    ]
    not_actions = []
  }

  assignable_scopes = [
    azurerm_resource_group.rg.id,
  ]
}

resource "azurerm_role_assignment" "reader" {
  scope                = azurerm_resource_group.rg.id
  role_definition_name = azurerm_role_definition.vault-reader.name
  principal_id         = azurerm_user_assigned_identity.msi.principal_id
}

resource "azurerm_key_vault" "vault" {
  name                = "ace-vault-kv"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tenant_id           = data.azurerm_subscription.primary.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_subscription.primary.tenant_id
    object_id = azurerm_user_assigned_identity.msi.principal_id

    key_permissions = [
      "get",
      "wrapKey",
      "unwrapKey",
    ]
    certificate_permissions = [
      "get",
    ]
    secret_permissions = [
      "get",
      "set",
    ]
  }

  # access policy for the user that is currently running terraform.
  access_policy {
    tenant_id = data.azurerm_subscription.primary.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "get",
      "list",
      "create",
      "delete",
      "purge",
      "update",
    ]
    certificate_permissions = [
      "get",
      "list",
      "create",
      "delete",
      "purge",
      "recover",
      "update",
    ]
    secret_permissions = [
      "get",
      "list",
    ]
  }

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }
}

resource "azurerm_virtual_network" "vnet" {
  name                = "vault-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "vault-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "vault-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "allow_ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "lbpip" {
  name                = "vault-loadbalancer-ip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = "ace-vault-demo"
}

resource "azurerm_public_ip" "pip" {
  name                = "vault-pip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_lb" "lb" {
  name                = "vault-lb"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Standard"

  frontend_ip_configuration {
    name                 = "frontend"
    public_ip_address_id = azurerm_public_ip.lbpip.id
  }
}

resource "azurerm_lb_backend_address_pool" "backend" {
  loadbalancer_id = azurerm_lb.lb.id
  name            = "backend"
}

resource "azurerm_lb_outbound_rule" "outbound" {
  resource_group_name     = azurerm_resource_group.rg.name
  loadbalancer_id         = azurerm_lb.lb.id
  name                    = "OutboundRule"
  protocol                = "All"
  backend_address_pool_id = azurerm_lb_backend_address_pool.backend.id

  frontend_ip_configuration {
    name = "frontend"
  }
}

resource "azurerm_network_interface" "nic" {
  name                = "vault-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "vault-nic-config"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

resource "azurerm_network_interface" "outbound" {
  name                = "vault-outbound-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "config"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "dynamic"
  }
}


resource "azurerm_network_interface_backend_address_pool_association" "lbassociation" {
  network_interface_id    = azurerm_network_interface.outbound.id
  ip_configuration_name   = "config"
  backend_address_pool_id = azurerm_lb_backend_address_pool.backend.id
}

resource "azurerm_network_interface_security_group_association" "nsgnic" {
  network_interface_id      = azurerm_network_interface.nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# Create a Linux virtual machine
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vault-vm"
  location              = var.location
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [
    azurerm_network_interface.nic.id,
    azurerm_network_interface.outbound.id,
  ]
  size                  = "Standard_D4s_v3"
  admin_username        = "azureuser"
  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  custom_data = filebase64("./bootstrap.sh")

  os_disk {
    name                 = "vault-os-disk"
    caching              = "ReadOnly"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 100
    diff_disk_settings {
      option = "Local"
    }
  }

  source_image_id = "/subscriptions/8643025a-c059-4a48-85d0-d76f51d63a74/resourceGroups/ace-vault-image/providers/Microsoft.Compute/images/ace-vault-image-small"
  // source_image_reference {
  //   publisher = "Canonical"
  //   offer     = "0001-com-ubuntu-server-focal"
  //   sku       = "20_04-lts"
  //   version   = "latest"
  // }

  boot_diagnostics {
    storage_account_uri = null
  }

  identity {
    type = "UserAssigned"
    identity_ids = [
      azurerm_user_assigned_identity.msi.id
    ]
  }
}


resource "azurerm_key_vault_certificate" "root" {
  name         = "vault-root"
  key_vault_id = azurerm_key_vault.vault.id

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 4096
      key_type   = "RSA"
      reuse_key  = true
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }

      trigger {
        lifetime_percentage = 10
      }
    }

    secret_properties {
      content_type = "application/x-pem-file"
    }

    x509_certificate_properties {
      # Server Authentication = 1.3.6.1.5.5.7.3.1
      # Client Authentication = 1.3.6.1.5.5.7.3.2
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]

      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]

      subject_alternative_names {
        dns_names = [azurerm_network_interface.nic.private_ip_address]
      }

      subject            = "CN=vault-root-ca"
      validity_in_months = 12
    }
  }
}

resource "azurerm_key_vault_key" "unseal" {
  name         = "unseal-key"
  key_vault_id = azurerm_key_vault.vault.id
  key_type     = "RSA"
  key_size     = 4096

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}

output "instance_ip_addr" {
  value = azurerm_public_ip.pip.ip_address
}

output "identity_id" {
  value = azurerm_user_assigned_identity.msi.id
}

output "identity_client_id" {
  value = azurerm_user_assigned_identity.msi.client_id
}

output "identity_principal_id" {
  value = azurerm_user_assigned_identity.msi.principal_id
}
