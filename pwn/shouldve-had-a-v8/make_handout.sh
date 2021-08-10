tar --owner="samsonites" --group="samsonites" \
    --exclude challenge/flag.txt \
    --transform 's|challenge|v8|' \
    -czvf handout.tar.gz challenge
