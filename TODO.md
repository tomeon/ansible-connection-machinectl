# TODO

## User resolution

From `local.py`:

```python
# Because we haven't made any remote connection we're running as
# the local user, rather than as whatever is configured in
# remote_user.
self._play_context.remote_user = getpass.getuser()
```

`machinectl` might need different logic because of the fact that it does allow
remote connections via `ssh`.
