#! /bin/bash

msg="$(date '+%m')$(date '+%d')_desktop"

git add .
git commit -m $msg 
git push -u nullcon2020 desktop
