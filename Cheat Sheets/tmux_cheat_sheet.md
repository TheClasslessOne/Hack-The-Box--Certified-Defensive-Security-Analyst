# 📝 tmux Cheat Sheet

## 🔹 Start & Exit
```bash
tmux                   # start new session
tmux new -s name       # start session with name
tmux attach -t name    # attach to existing session
tmux ls                # list sessions
tmux kill-session -t name  # kill specific session
tmux detach            # detach (Ctrl+b d)
```

---

## 🔹 Sessions
- `Ctrl+b s` → list sessions  
- `Ctrl+b $` → rename current session  
- `unset TMUX; tmux attach -t name` → avoid nesting  

---

## 🔹 Windows (tabs in tmux)
- `Ctrl+b c` → create new window  
- `Ctrl+b ,` → rename window  
- `Ctrl+b w` → list windows  
- `Ctrl+b n` → next window  
- `Ctrl+b p` → previous window  
- `Ctrl+b &` → close window  

---

## 🔹 Panes (splits)
- `Ctrl+b %` → vertical split  
- `Ctrl+b "` → horizontal split  
- `Ctrl+b x` → kill pane  
- `Ctrl+b o` → switch pane  
- `Ctrl+b ;` → last pane  
- `Ctrl+b q` → show pane numbers  
- `Ctrl+b ⬆/⬇/⬅/➡` → move between panes  

---

## 🔹 Resizing Panes
```bash
Ctrl+b :resize-pane -U 5   # resize up
Ctrl+b :resize-pane -D 5   # resize down
Ctrl+b :resize-pane -L 5   # resize left
Ctrl+b :resize-pane -R 5   # resize right
```

---

## 🔹 Copy Mode
- `Ctrl+b [` → enter copy mode (scroll/history)  
- `Space` → start selection  
- `Enter` → copy selection  
- `Ctrl+b ]` → paste  

---

## 🔹 Misc
- `Ctrl+b t` → show clock  
- `Ctrl+b ?` → show all keybindings  
- `Ctrl+b :` → enter command mode  

---

## 🔹 Workflow Tips
- **Detach often**: `Ctrl+b d` keeps session alive in background  
- **Use names**: `tmux new -s htb` → easier to reattach (`tmux attach -t htb`)  
- **Don’t nest unless necessary**: `unset TMUX` if you accidentally start tmux inside tmux  

---

# 🚀 Quick-Start Workflow (HTB Lab Example)

## 1. Start a new session
```bash
tmux new -s htb
```

---

## 2. Organize windows
- `Ctrl+b c` → create new windows
- Example setup:
  - **Window 0** → `recon` (nmap, enum)
  - **Window 1** → `www` (web fuzzing, curl)
  - **Window 2** → `exploit` (scripts, payloads)
  - **Window 3** → `notes` (vim/nano for jotting findings)

Rename each with:
```bash
Ctrl+b ,   # then type new name
```

---

## 3. Split panes inside windows
- Recon window (`recon`):
  - Left pane: `nmap`
  - Right pane: open notes (`vim`) to jot ports  
  ```bash
  Ctrl+b %   # vertical split
  Ctrl+b "   # horizontal split
  ```

- Web window (`www`):
  - Top pane: run `ffuf`/`gobuster`
  - Bottom pane: live `curl`/`httpie`

---

## 4. Navigation shortcuts
- `Ctrl+b n` → next window  
- `Ctrl+b p` → previous window  
- `Ctrl+b w` → choose window  
- `Ctrl+b o` → switch panes  
- `Ctrl+b q` → show pane numbers  

---

## 5. Detach & Reattach
```bash
Ctrl+b d                # detach, keeps work running
tmux attach -t htb      # reattach later
tmux ls                 # list sessions if multiple
```

---

## 6. Cleanup
```bash
tmux kill-session -t htb
```

---

✅ This workflow gives you a clean environment:
- **Session:** `htb`
- **Windows:** recon / www / exploit / notes
- **Panes:** logical splits for tools

Keeps labs organized & avoids terminal chaos.
