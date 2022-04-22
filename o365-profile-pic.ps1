Import-Module ExchangeOnlineManagement 
Connect-ExchangeOnline -UserPrincipalName andrew.davis@vinebrookhomes.com 

Set-UserPhoto -Identity "user.name@domain.xyz" -PictureData ([System.IO.File]::ReadAllBytes("C:\path\to\img\image.jpg")) -Confirm:$false
