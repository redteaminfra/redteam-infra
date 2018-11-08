# Red Team Hosted Infrastructure

# What

This project houses reference deployment recipies that can be used to build Red Team Infrastructure. As such, there are no security guarantees or promises. Use at your own risk.

# Contributing

See `contributing.md`

## Setup

View `Internal` for hosting on an internal host or `External` for hosting on AWS.

This project currently relies on Vagrant version 2.0.1. 2.1 introduced new features that have not been ported to the Vagrantfiles. 

## What What?  In The Puppet

See `puppet/README.md` for information on puppet modules

## SSH Users

Both `Internal` and `External` use a ssh submodule

```
git submodule init
git submodule update
```

## Rebasing Op repos

### Perquisite

1. Add original repo as remote

```
git remote add infra git@github.com:intel/redteam-infra
```

### Workflow

This can probably be abbreviated, this is what I do.

1. Observe curent state

    ```
    $ git show -s --pretty=short infra/master
    commit 52d09519a84bf4cca3af80287958e506627d755f (infra/master)
    Author: ctimzen <topher.timzen@intel.com>


    $ git show -s --pretty=short master
    commit a2a80ce163ecd131ee2b34293acec83a5aed4153 (HEAD -> master, origin/master, origin/HEAD)
    Author: Michael Leibowitz <michael.leibowitz@intel.com>


    ```

1. Find the common ancestor

    ```
    $ git merge-base master infra/master
    ```

1. Checkout your "feature" branch

    This is counter-intuitive, but master is you feature branch.  We'll make a branch and then, since it will be branched from HEAD, will be our feature branch

    ```
    git checkout -b feature
    ```

1. Switch back to master and reset back to common ancenstor

    ```
    git checkout master
    git reset --hard <commit given in merge-base>
    ```

1. Pull infra master

    ```
    git pull infra master
    ```

1. checkout and rebase feature

    ```
    git checkout feature
    git rebase master
    ```

1. merge feature to master

    ```
    git checkout master
    git merge feature
    git branch -d feature
    ```

1. Push for victory

    ```
    git push --force origin master
    git push --force homebase-opname:/var/lib/git/infra
    ```
