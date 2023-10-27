google-chrome
=========

Install Google Chrome.

There are a number of extensions that are installed by default.
- uBlock Origin
- Privacy Badger
- Proxy SwitchyOmega

There are also a number of preconfigured settings. View `files/chrome-policies.json` for more details.

You can read more about the policies here: https://archive.ph/3x8sV

Example Playbook
----------------

```yml
- hosts: servers
  roles:
   - google-chrome
```
