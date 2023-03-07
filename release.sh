#!/bin/bash
set -e

if [[ "$#" != "1" ]] || [[ ! "$1" =~ ^(patch|minor|major)$ ]]; then
  echo -e "Usage: $0 \033[1mpatch|minor|major\033[0m"
  exit 1
fi

for command in git jq; do
    if ! command -v $command >/dev/null; then
        echo -e "Install \033[1m$command\033[0m"
        exit 1
    fi
done

INCREMENT=$1

update_package() {
    cd $1
    npm run build
    npm version $INCREMENT --no-git-tag-version
    npm publish
    cd - &>/dev/null
}

update_package client
update_package middleware
version=`cat middleware/package.json | jq -r .version`
cd server
npm i @neoskop/ethereal-secrets-middleware@$version
cd -
update_package server
cd server
docker build -t neoskop/ethereal-secrets-server:latest -t neoskop/ethereal-secrets-server:$version .
docker push neoskop/ethereal-secrets-server:latest
docker push neoskop/ethereal-secrets-server:$version
cd - &>/dev/null
git add .
git commit -m "chore: Bump version to $version"
git push