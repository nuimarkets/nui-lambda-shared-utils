# nui-lambda-shared-utils

The maintained package is **[nui-python-shared-utils](https://pypi.org/project/nui-python-shared-utils/)**. Install it directly:

```bash
pip install nui-python-shared-utils
```

This distribution is a thin redirect that depends on `nui-python-shared-utils`, so an existing `pip install nui-lambda-shared-utils` keeps resolving. It ships no code of its own.

Import from `nui_shared_utils`:

```python
from nui_shared_utils import SlackClient
```

Point your `requirements.txt` at the maintained package:

```diff
- nui-lambda-shared-utils[powertools]
+ nui-python-shared-utils[powertools]
```
