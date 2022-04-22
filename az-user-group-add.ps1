Import-Module ExchangeOnlineManagement 
Add-UnifiedGroupLinks 
Connect-ExchangeOnline 
Add-UnifiedGroupLinks –Identity "o365_group_name@vinebrookhomes.com" –LinkType Members  –Links "user.name@domain.xyz"
