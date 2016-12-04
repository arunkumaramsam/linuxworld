to create a script to add the multiple users 
#!/bin/bash

# Assign file descriptors to users and passwords files
exec 3< users.txt
exec 4< passwords.txt
exec 5< passwords.txt

# Read user and password
while read iuser <&3 && read ipasswd <&4 ; do
  # Just print this for debugging
  printf "\tCreating user: %s with password: %s\n" $iuser $ipasswd
  # Create the user with adduser (you can add whichever option you like)
  useradd    $iuser
  # Assign the password to the user, passwd must read it from stdin
  passwd  --stdin   "$iuser" <<<"$ipasswd "
done

files and content
#cat users.txt
arun
kumar
amsam
selvi
aish
hindu
jothi
nandini

