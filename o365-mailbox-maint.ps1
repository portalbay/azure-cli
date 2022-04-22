
#Find all users with a mailbox forward setup
Get-Mailbox | select UserPrincipalName,ForwardingSmtpAddress,DeliverToMailboxAndForward | Export-csv .\o365_forward_users.csv -NoTypeInformation 

#Find all users with unlimited mailbox storage
Get-mailbox -ResultSize unlimited | select DisplayName,ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward | where {$_.DeliverToMailboxAndForward -ne $False} 

#Getmailbox stats
Get-MailboxStatistics -Identity user.name@domain.xyz | Format-List 
