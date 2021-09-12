variable "image_name" {
  type    = string
  default = "ace-vault-image-test"
}

variable "resource_group_name" {
  type    = string
  default = "ace-vault-image"
}

variable "storage_account_name" {
  type = string 
  default = "acepackervhds"
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "subscription_id" {
  type    = string
  default = "8643025a-c059-4a48-85d0-d76f51d63a74"
}

source "azure-arm" "vault" {
  subscription_id = var.subscription_id
  client_id = file("client_id.txt")
  client_secret = file("client_secret.txt")

  build_resource_group_name = "${var.resource_group_name}-pkr"

  // managed_image_resource_group_name = var.resource_group_name
  // managed_image_name                = var.image_name

  resource_group_name = var.resource_group_name
  // location = var.location
  storage_account = var.storage_account_name
  capture_container_name = "deleted"
  capture_name_prefix = "{{timestamp}}"
  // temp_resource_group_name = "ace-pkr-temp-{{timestamp}}"

  // image_url = "https://acepackervhds.blob.core.windows.net/system/Microsoft.Compute/Images/vhd/1614917266-osDisk.bf670f31-bad7-4a24-975b-9f33c0fbf0f7.vhd"
  os_type         = "Linux"
  image_publisher = "Canonical"
  image_offer     = "0001-com-ubuntu-server-focal"
  image_sku       = "20_04-lts"

  vm_size           = "Standard_D8s_v3"
  os_disk_size_gb   = 30
  disk_caching_type = "ReadOnly"
}

build {
  sources = [
    "source.azure-arm.vault",
  ]

  // provisioner "shell" {
  //   script       = "image.sh"
  //   pause_before = "10s"
  //   timeout      = "10s"
  // }

  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E sh '{{ .Path }}'"
    inline = [
      "apt-get update",
      "apt-get upgrade -y",
      "/usr/sbin/waagent -force -deprovision+user && export HISTSIZE=0 && sync"
    ]
    inline_shebang = "/bin/sh -x"
  }
}
