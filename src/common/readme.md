# Common Package

> Collection of shared modules used throughout the breadcrumbs project

## Installing in Your Project

To use the `common` package in your project, run the following command:

```bash
pip install .
```

## Development Guide

To add additional common modules or edit the functionality, you can modify these files directly.
Then, run `pip install .` again to reinstall the package with your changes.

### Adding Additional Dependencies

To add additional dependencies, add the required package to the `dependencies` in the [pyproject.toml](pyproject.toml)
file.

```
...
dependencies = [
    "foo==1.0.0",
    <YOUR-PACKAGE-HERE>,
]
```

This will install the required dependencies when a user runs `pip install`
