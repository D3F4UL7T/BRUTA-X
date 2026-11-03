# Backup & Recovery

```python
from app.services.backup import create_backup, verify_backup, restore_backup
meta = create_backup()
verify_backup(meta["file"])
restore_backup(meta["file"], confirm=True)  # creates pre_restore recovery point
```
