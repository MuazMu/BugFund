# Migration versions

Numbered Alembic migration scripts live here. Generate one from the current
ORM metadata:

```bash
make migrations m="initial schema"     # alembic revision --autogenerate
make migrate                            # alembic upgrade head
```

The first autogenerate will create all tables defined under
`control_plane/db/models/`. Review the generated script before applying it.
