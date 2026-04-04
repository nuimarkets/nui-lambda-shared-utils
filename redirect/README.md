# nui-lambda-shared-utils (redirect)

This package has been renamed to **[nui-python-shared-utils](https://pypi.org/project/nui-python-shared-utils/)**.

Install the new package directly:

```bash
pip install nui-python-shared-utils
```

This redirect package depends on `nui-python-shared-utils` and re-exports
`nui_lambda_shared_utils` for backwards compatibility. Existing code continues
to work without changes.

To migrate, update your `requirements.txt`:

```diff
- nui-lambda-shared-utils[powertools]
+ nui-python-shared-utils[powertools]
```

Import names remain unchanged during the transition period:

```python
# Both work
from nui_lambda_shared_utils import SlackClient
```
