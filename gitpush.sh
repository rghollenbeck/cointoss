#!/bin/bash

# A script to push changes to the version-0.1.1 branch of cointoss

# Check if there are changes to commit
if [[ $(git status --porcelain) ]]; then
  echo "Changes detected. Adding files..."
  git add .

  echo "Enter commit message: "
  read commit_message

  echo "Committing changes..."
  git commit -m "$commit_message"

  echo "Pushing changes to origin/version-0.1.1..."
  git push origin version-0.1.1
else
  echo "No changes to push!"
fi

