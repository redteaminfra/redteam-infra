# Red Team Hosted Infrastructure

# What

This project houses reference deployment recipes that can be used to build Red Team Infrastructure. As such, there are no security guarantees or promises. Use at your own risk.

This infrastructure was discussed at CanSecWest 2019 and the slides can be found [here](https://speakerdeck.com/tophertimzen/attack-infrastructure-for-the-modern-red-team)

# Contributing

See `contributing.md`

## Setup

View `external/cloudProvider` for setup instructions

## What What?  In The Puppet

See `puppet/README.md` for information on puppet modules

## Rebasing Op repos

### Prerequisite

1. Add original repo as remote

```
git remote add infra git@github.com:redteam-infra/redteam-infra
```

### Workflow

This can probably be abbreviated, this is what I do.

1. Observe current state

    ```
    $ git show -s --pretty=short infra/master
    commit 52d09519a84bf4cca3af80287958e506627d755f (infra/master)
    Author: ctimzen <topher.timzen@red.com>


    $ git show -s --pretty=short master
    commit a2a80ce163ecd131ee2b34293acec83a5aed4153 (HEAD -> master, origin/master, origin/HEAD)
    Author: Michael Leibowitz <michael.leibowitz@red.team>


    ```

2. Find the common ancestor

    ```
    $ git merge-base master infra/master
    ```

3. Checkout your "feature" branch

    This is counter-intuitive, but master is you feature branch.  We'll make a branch and then, since it will be branched from HEAD, will be our feature branch

    ```
    git checkout -b feature
    ```

4. Switch back to master and reset back to common ancenstor

    ```
    git checkout master
    git reset --hard <commit given in merge-base>
    ```

5. Pull infra master

    ```
    git pull infra master
    ```

6. checkout and rebase feature

    ```
    git checkout feature
    git rebase master
    ```

7. merge feature to master

    ```
    git checkout master
    git merge feature
    git branch -d feature
    ```

8. Push for victory

    ```
    git push --force origin master
    git push --force homebase-opname:/var/lib/git/infra
    ```
