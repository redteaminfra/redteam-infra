if [[ ! -f "$HOME/.vnc_configured" ]]; then
  vncpasswd -f <<< $(whoami) > ~/.vnc/passwd
  chmod 600 ~/.vnc/passwd

  PORT=$(($(id -u) - 6000 + 1))

  systemctl --user daemon-reload
  systemctl --user enable vncserver@$PORT.service > /dev/null 2>&1
  systemctl --user start vncserver@$PORT.service > /dev/null 2>&1

  touch "$HOME/.vnc_configured"
fi
