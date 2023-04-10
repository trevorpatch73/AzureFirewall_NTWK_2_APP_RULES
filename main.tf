terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}
provider "azurerm" {
  features {}
}

// Variables
variable "MyAppAdmin" {
  type    = string
  default = "MyAppAdmin"
}
variable "MyAppAdminPwd" {
  type        = string
  description = "Maps too Environmental Variable: TF_VAR_MyAppAdminPwd"
}
variable "MyAppAdminVmSize" {
  type    = string
  default = "Standard_A2_v2"
}

// Global
resource "azurerm_resource_group" "MAC_UE_TENANT_PROD_MY_APP_RG" {
  name     = "MAC-UE-TENANT-PROD-MY-APP-RG"
  location = "East US"
}
resource "azurerm_resource_group" "MAC_UE_TENANT_PROD_NETOPS_RG" {
  name     = "MAC-UE-TENANT-PROD-NETOPS-RG"
  location = "East US"
}

// Hub
resource "azurerm_virtual_network" "MAC_UE_TENANT_HUB_PROD_VNET" {
  name                = "MAC-UE-TENANT-HUB-PROD-VNET"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  address_space       = ["30.0.0.0/16"]
}
resource "azurerm_subnet" "MAC_UE_TENANT_HUB_PROD_GATEWAY_SUBNET" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name = azurerm_virtual_network.MAC_UE_TENANT_HUB_PROD_VNET.name
  address_prefixes     = ["30.0.0.0/24"]
}
resource "azurerm_public_ip" "MAC_UE_TENANT_HUB_PROD_ER_VNG_PIP" {
  name                = "MAC-UE-TENANT-HUB-PROD-ER-VNG-PIP"
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  allocation_method   = "Dynamic"
}
resource "azurerm_virtual_network_gateway" "MAC_UE_TENANT_HUB_EXPRESS_ROUTE_VIRTUAL_NETWORK_GATEWAY" {
  name                = "MAC-UE-TENANT-HUB-ER-VNG"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  sku                 = "Standard"
  type                = "ExpressRoute"
  vpn_type            = "PolicyBased"
  ip_configuration {
    name                          = "MAC-UE-TENANT-HUB-ER-VNG-IP-CONFIGURATION"
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.MAC_UE_TENANT_HUB_PROD_GATEWAY_SUBNET.id
    public_ip_address_id          = azurerm_public_ip.MAC_UE_TENANT_HUB_PROD_ER_VNG_PIP.id
  }
}
resource "azurerm_route_table" "MAC_UE_TENANT_HUB_PROD_GATEWAY_SUBNET_RT" {
  name                = "MAC-UE-TENANT-HUB-PROD-GATEWAY-SUBNET-RT"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
}
resource "azurerm_route" "MAC_UE_TENANT_HUB_PROD_GATEWAY_SUBNET_RT_30_4_0_0" {
  name                   = "MAC-UE-TENANT-HUB-PROD-GATEWAY-SUBNET-RT-30-4-0-0"
  resource_group_name    = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  route_table_name       = azurerm_route_table.MAC_UE_TENANT_HUB_PROD_GATEWAY_SUBNET_RT.name
  address_prefix         = "30.4.0.0/24"
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL.ip_configuration[0].private_ip_address
}
resource "azurerm_subnet" "MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_SUBNET" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name = azurerm_virtual_network.MAC_UE_TENANT_HUB_PROD_VNET.name
  address_prefixes     = ["30.0.1.0/24"]
}
resource "azurerm_subnet" "MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_MANAGEMENT_SUBNET" {
  name                 = "AzureFirewallManagementSubnet"
  resource_group_name  = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name = azurerm_virtual_network.MAC_UE_TENANT_HUB_PROD_VNET.name
  address_prefixes     = ["30.0.2.0/24"]
}
resource "azurerm_public_ip" "MAC_UE_TENANT_HUB_PROD_AZURE_FW_PIP" {
  name                = "MAC-UE-TENANT-HUB-PROD-AZURE-FW-PIP"
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  allocation_method   = "Static"
  sku                 = "Standard"
}
resource "azurerm_public_ip" "MAC_UE_TENANT_HUB_PROD_AZURE_FW_MGMT_PIP" {
  name                = "MAC-UE-TENANT-HUB-PROD-AZURE-FW-MGMT-PIP"
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  allocation_method   = "Static"
  sku                 = "Standard"
}
resource "azurerm_firewall_policy" "MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_POL" {
  name                = "MAC-UE-TENANT-HUB-PROD-AZURE-FIREWALL-POLICY"
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
}
resource "azurerm_firewall" "MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL" {
  name                = "MAC-UE-TENANT-HUB-PROD-AZURE-FIREWALL"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_POL.id

  ip_configuration {
    name                 = "AzureFirewallSubnet_IP_Configuration"
    subnet_id            = azurerm_subnet.MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_SUBNET.id
    public_ip_address_id = azurerm_public_ip.MAC_UE_TENANT_HUB_PROD_AZURE_FW_PIP.id
  }

  management_ip_configuration {
    name                 = "AzureFirewallManagementSubnet_IP_Configuration"
    subnet_id            = azurerm_subnet.MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_MANAGEMENT_SUBNET.id
    public_ip_address_id = azurerm_public_ip.MAC_UE_TENANT_HUB_PROD_AZURE_FW_MGMT_PIP.id
  }
}
resource "azurerm_firewall_policy_rule_collection_group" "MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_POL_RCG" {
  name               = "MAC-UE-TENANT-HUB-PROD-AZURE-FIREWALL-POL-RCG"
  firewall_policy_id = azurerm_firewall_policy.MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL_POL.id
  priority           = 500
  
    network_rule_collection {
    name     = "LAYER_4_RULES"
    priority = 400
    action   = "Allow"

    rule {
      name                  = "PING"
      protocols             = ["ICMP"]
      source_addresses      = ["*"]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }

    rule {
      name                  = "SSH"
      protocols             = ["TCP"]
      source_addresses      = azurerm_virtual_network.MAC_UE_TENANT_PROD_BASTION_VNET.address_space
      destination_addresses = ["30.0.0.0/8"]
      destination_ports     = ["22"]
    }

    rule {
      name                  = "HTTP"
      protocols             = ["TCP"]
      source_addresses      = ["30.0.0.0/8"]
      destination_addresses = ["*"]
      destination_ports     = ["80"]
    }

    rule {
      name                  = "HTTPS"
      protocols             = ["TCP"]
      source_addresses      = ["30.0.0.0/8"]
      destination_addresses = ["*"]
      destination_ports     = ["443"]
    }

  }
}
// SPOKE
resource "azurerm_virtual_network" "MAC_UE_TENANT_PROD_BASTION_VNET" {
  name                = "MAC-UE-TENANT-PROD-BASTION-VNET"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  address_space       = ["30.4.0.0/24"]
}
resource "azurerm_subnet" "MAC_UE_TENANT_PROD_BASTION_SUBNET" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name = azurerm_virtual_network.MAC_UE_TENANT_PROD_BASTION_VNET.name
  address_prefixes     = ["30.4.0.0/25"]
}
resource "azurerm_subnet" "MAC_UE_TENANT_PROD_JUMPHOST_SUBNET" {
  name                 = "MAC-UE-TENANT-PROD-JUMPHOST-SUBNET"
  resource_group_name  = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name = azurerm_virtual_network.MAC_UE_TENANT_PROD_BASTION_VNET.name
  address_prefixes     = ["30.4.0.128/25"]
}
resource "azurerm_route_table" "MAC_UE_TENANT_PROD_JUMPHOST_RT" {
  name                = "MAC-UE-TENANT-PROD-JUMPHOST-RT"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name

  route {
    name                   = "default_route"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.MAC_UE_TENANT_HUB_PROD_AZURE_FIREWALL.ip_configuration[0].private_ip_address
  }
}
resource "azurerm_subnet_route_table_association" "MAC_UE_TENANT_PROD_JH_RT_ASSOC" {
  subnet_id      = azurerm_subnet.MAC_UE_TENANT_PROD_JUMPHOST_SUBNET.id
  route_table_id = azurerm_route_table.MAC_UE_TENANT_PROD_JUMPHOST_RT.id
}


// Peering
resource "azurerm_virtual_network_peering" "MAC_UE_TENANT_PROD_BASTION_PEER_HUB" {
  name                      = "MAC-UE-TENANT-PROD-BASTION-PEER-HUB"
  resource_group_name       = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name      = azurerm_virtual_network.MAC_UE_TENANT_HUB_PROD_VNET.name
  remote_virtual_network_id = azurerm_virtual_network.MAC_UE_TENANT_PROD_BASTION_VNET.id

  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true

  depends_on = [
    azurerm_virtual_network_gateway.MAC_UE_TENANT_HUB_EXPRESS_ROUTE_VIRTUAL_NETWORK_GATEWAY,
    azurerm_virtual_network.MAC_UE_TENANT_PROD_BASTION_VNET
  ]
}
resource "azurerm_virtual_network_peering" "MAC_UE_TENANT_PROD_BASTION_PEER_SPOKE" {
  depends_on = [azurerm_virtual_network_gateway.MAC_UE_TENANT_HUB_EXPRESS_ROUTE_VIRTUAL_NETWORK_GATEWAY]

  name                      = "MAC-UE-TENANT-PROD-BASTION-PEER-SPOKE"
  resource_group_name       = azurerm_resource_group.MAC_UE_TENANT_PROD_NETOPS_RG.name
  virtual_network_name      = azurerm_virtual_network.MAC_UE_TENANT_PROD_BASTION_VNET.name
  remote_virtual_network_id = azurerm_virtual_network.MAC_UE_TENANT_HUB_PROD_VNET.id

  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  use_remote_gateways          = true
}



// Bastion
resource "azurerm_public_ip" "MAC_UE_TENANT_PROD_BASTION_01_PIP" {
  name                = "MAC-UE-TENANT-PROD-BASTION-01-PIP"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
  allocation_method   = "Static"
  sku                 = "Standard"
}
resource "azurerm_bastion_host" "MAC_UE_TENANT_PROD_BASTION_01" {
  name                = "MAC-UE-TENANT-PROD-BASTION-01"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.MAC_UE_TENANT_PROD_BASTION_SUBNET.id
    public_ip_address_id = azurerm_public_ip.MAC_UE_TENANT_PROD_BASTION_01_PIP.id
  }
}

resource "azurerm_application_security_group" "MAC_UE_TENANT_PROD_MY_APP_JH_ASG" {
  name                = "MAC-UE-TENANT-PROD-MY-APP-JH-ASG"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
}
resource "azurerm_network_security_group" "MAC_UE_TENANT_PROD_MY_APP_JH_NSG" {
  name                = "MAC-UE-TENANT-PROD-MY-APP-JH-NSG"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
}
resource "azurerm_network_security_rule" "MAC_UE_TENANT_PROD_MY_APP_JH_ALW_OUT_SSH" {
  name                   = "MAC-UE-TENANT-PROD-MY-APP-JH-ALW-OUT-SSH"
  priority               = 2000
  direction              = "Outbound"
  access                 = "Allow"
  protocol               = "Tcp"
  source_port_range      = "*"
  destination_port_range = "22"
  source_application_security_group_ids = [
    azurerm_application_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_ASG.id
  ]
  destination_address_prefix  = "30.0.0.0/8"
  resource_group_name         = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
  network_security_group_name = azurerm_network_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_NSG.name
}
resource "azurerm_network_security_rule" "MAC_UE_TENANT_PROD_MY_APP_JH_ALW_OUT_HTTP" {
  name                   = "MAC-UE-TENANT-PROD-MY-APP-JH-ALW-OUT-HTTP"
  priority               = 2010
  direction              = "Outbound"
  access                 = "Allow"
  protocol               = "Tcp"
  source_port_range      = "*"
  destination_port_range = "80"
  source_application_security_group_ids = [
    azurerm_application_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_ASG.id
  ]
  destination_address_prefix  = "0.0.0.0/0"
  resource_group_name         = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
  network_security_group_name = azurerm_network_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_NSG.name
}
resource "azurerm_network_security_rule" "MAC_UE_TENANT_PROD_MY_APP_JH_ALW_OUT_HTTPS" {
  name                   = "MAC-UE-TENANT-PROD-MY-APP-JH-ALW-OUT-HTTP"
  priority               = 2020
  direction              = "Outbound"
  access                 = "Allow"
  protocol               = "Tcp"
  source_port_range      = "*"
  destination_port_range = "443"
  source_application_security_group_ids = [
    azurerm_application_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_ASG.id
  ]
  destination_address_prefix  = "0.0.0.0/0"
  resource_group_name         = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
  network_security_group_name = azurerm_network_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_NSG.name
}

resource "azurerm_network_interface" "MAC-UE-TENANT-PROD-MY-APP-JH-01_NIC_01_DYN" {
  name                = "MAC-UE-TENANT-PROD-MY-APP-JH-01_NIC_01_DYN"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.MAC_UE_TENANT_PROD_JUMPHOST_SUBNET.id
    private_ip_address_allocation = "Dynamic"
  }
}
resource "azurerm_network_interface_security_group_association" "MAC_UE_TENANT_PROD_MY_APP_JH_01_NIC_01_SG_ASSOC" {
  network_interface_id      = azurerm_network_interface.MAC-UE-TENANT-PROD-MY-APP-JH-01_NIC_01_DYN.id
  network_security_group_id = azurerm_network_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_NSG.id
}
resource "azurerm_network_interface_application_security_group_association" "MAC_UE_TENANT_PROD_MY_APP_JH_01_NIC_01_ASG_ASSOC" {
  network_interface_id          = azurerm_network_interface.MAC-UE-TENANT-PROD-MY-APP-JH-01_NIC_01_DYN.id
  application_security_group_id = azurerm_application_security_group.MAC_UE_TENANT_PROD_MY_APP_JH_ASG.id
}
resource "azurerm_linux_virtual_machine" "MACUETNTPMAJH01" {
  name                = "MACUETNTPMAJH01"
  location            = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.location
  resource_group_name = azurerm_resource_group.MAC_UE_TENANT_PROD_MY_APP_RG.name
  size                = var.MyAppAdminVmSize
  network_interface_ids = [
    azurerm_network_interface.MAC-UE-TENANT-PROD-MY-APP-JH-01_NIC_01_DYN.id,
  ]

  admin_username                  = var.MyAppAdmin
  admin_password                  = var.MyAppAdminPwd
  disable_password_authentication = false

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

// Outputs
output "bastion" {
  value = "Bastion: ${azurerm_public_ip.MAC_UE_TENANT_PROD_BASTION_01_PIP.ip_address}"
}
output "MyAppAdmin" {
  value = "Username: ${var.MyAppAdmin}"
}
output "MyAppAdminPwd" {
  value = "Password: ${var.MyAppAdminPwd}"
}
