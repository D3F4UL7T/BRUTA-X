# Performance notes

- SQLite indexes on assets.value/type and notifications.read
- Graph loads max 200 nodes per refresh
- Job worker pool limits concurrency
- Large tables should be filtered via search rather than loading all history
