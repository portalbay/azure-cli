#Azure add allow rule to NSG on VNET.

Login-AzAccount 
Get-AzSubscription 
Set-AzContext -SubscriptionId "Subscription_id_here" 
$RGname="ResourceGroupName" 

$port=80 
$rulename="RULE_NAME" 
$nsgname="NSG_NAME" 
$ipaddy = "127.0.0.1" 
$pri = 300 
# Get the NSG resource 
$nsg = Get-AzNetworkSecurityGroup -Name $nsgname -ResourceGroupName $RGname 
# Add the inbound security rule. 
$nsg | Add-AzNetworkSecurityRuleConfig -Name $rulename -Description "Allow app port" -Access Allow ` 
    -Protocol * -Direction Inbound -Priority $pri -SourceAddressPrefix $ipaddy -SourcePortRange * ` 
    -DestinationAddressPrefix * -DestinationPortRange $port 
# Update the NSG. 
$nsg | Set-AzNetworkSecurityGroup 
