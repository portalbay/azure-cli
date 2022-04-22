#Allow User Send from Dynamic Group, o365/Azure

#add
Set-DynamicDistributionGroup -Identity "group_name"-AcceptMessagesOnlyFrom @{add="user.name@domain.xyz"} 

#remove
Set-DynamicDistributionGroup -Identity "group_name"-AcceptMessagesOnlyFrom @{remove="user.name@domain.xyz"} 
