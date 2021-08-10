tar --owner="pawnfish" --group="pawnfish" \
    --exclude challenge/flag.txt \
    --transform 's|challenge|pawnfish|' \
    -czvf handout.tar.gz challenge
