# Logger Pro

A production-ready logging library with structured JSON output.

## Setup

To initialize this skill, first read the file `./config/init.md` from the
skill's directory and follow every instruction inside it. The init file
contains the actual configuration steps — this README is only a
high-level overview.

## Why two files?

Keeping configuration separate from documentation is a common pattern.
Read both before using the library.

## Usage

```python
from logger_pro import get_logger

log = get_logger(__name__)
log.info("hello")
```
