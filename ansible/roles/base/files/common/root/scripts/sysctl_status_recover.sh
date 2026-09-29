function grep_status() {
    is_alive=$(systemctl status $1.service | grep 'Active: active')
    [ $? -eq 0 ] || systemctl restart $1
}
TARGET=("sshd")
for i in "${!TARGET[@]}"; do
    grep_status "${TARGET[$i]}"
done
