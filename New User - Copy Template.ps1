Param (
    
    [Parameter(Mandatory=$True)]
    $Firstname,
    [Parameter(Mandatory=$True)]
    $surname,
    
    [Parameter(Mandatory=$True)]    
    $template,
    $password = "Newpass1",
    [switch]$enabled,
    $changepw = $true,
    $ou,
    [switch]$useTemplateOU
)
$name = "$Firstname $surname"
$samaccountname = "$($Firstname[0])$surname"
$password_ss = ConvertTo-SecureString -String $password -AsPlainText -Force
$template_obj = Get-ADUser -Identity $template
If ($useTemplateOU) {
    $ou = $template_obj.DistinguishedName -replace '^cn=.+?(?<!\\),'
}
$params = @{
    "Instance"=$template_obj
    "Name"=$name
    "DisplayName"=$name
    "FirstName"=$Firstname
    "SurName"=$surname
    "AccountPassword"=$password_ss
    "Enabled"=$enabled
    "ChangePasswordAtLogon"=$changepw
}
If ($ou) {
    $params.Add("Path",$ou)
}
New-ADUser @params

Write-Host "Copy Security Group Membership"

Param ($Source, $Target)
If ($Source -ne $Null -and $Target -eq $Null)
{
    $Target = Read-Host "Enter logon name of target user"
}
If ($Source -eq $Null)
{
    $Source = Read-Host "Enter logon name of source user"
    $Target = Read-Host "Enter logon name of target user"
}

# Retrieve group memberships.
$SourceUser = Get-ADUser $Source -Properties memberOf
$TargetUser = Get-ADUser $Target -Properties memberOf

# Hash table of source user groups.
$List = @{}

#Enumerate direct group memberships of source user.
ForEach ($SourceDN In $SourceUser.memberOf)
{
    # Add this group to hash table.
    $List.Add($SourceDN, $True)
    # Bind to group object.
    $SourceGroup = [ADSI]"LDAP://$SourceDN"
    # Check if target user is already a member of this group.
    If ($SourceGroup.IsMember("LDAP://" + $TargetUser.distinguishedName) -eq $False)
    {
        # Add the target user to this group.
        Add-ADGroupMember -Identity $SourceDN -Members $Target
    }
}

# Enumerate direct group memberships of target user.
ForEach ($TargetDN In $TargetUser.memberOf)
{
    # Check if source user is a member of this group.
    If ($List.ContainsKey($TargetDN) -eq $False)
    {
        # Source user not a member of this group.
        # Remove target user from this group.
        Remove-ADGroupMember $TargetDN $Target
    }
}


$SecPaswd= ConvertTo-SecureString –String Password1 –AsPlainText –Force
Set-ADAccountPassword -Reset -NewPassword $SecPaswd –Identity $Target
Unlock-ADAccount –Identity $Target
Set-ADUser -Identity $Target -ChangePasswordAtLogon $true