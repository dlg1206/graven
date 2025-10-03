# Contributing to Graven

If you are looking to contribute to this project and want to open a GitHub 
pull request ("PR"), there are a few guidelines of what we are looking 
for in patches. Make sure you go through this document and ensure that 
your code proposal is aligned.

## Setting up your environment

Follow the [database setup](readme.md#starting-the-database) and [local deployment](readme.md#local-deployment) guide for installing 
graven locally.

## Adding a feature or fix

There are a few outstanding [issues](https://github.com/dlg1206/graven/issues) 
if you'd just like to contribute. If you find a bug or want to add a new 
feature, please create a new issue describing the bug or feature for tracking.

## Commit guidelines

Please follow good commit practices: detailed small and frequent commits. This
project follows [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) as a standard commit convention.


## Lint your changes

To maintain consistent coding practices, this projects use pylint. You can 
install and run pylint like so:
```bash
pip install pylint
pylint --fail-under=6.0 .
```

Please ensure your changes follow the lint rules set in the `.pylint` file.

## Pull Request

When creating a PR, please use a brief but descriptive title and detail your 
changes in the body. At the end of the body, please use the GitHub issue 
[closing feature](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/using-keywords-in-issues-and-pull-requests#linking-a-pull-request-to-an-issue) to reference the issue created as outlined in the 
[Adding a feature or fix](#adding-a-feature-or-fix) section like so:

```markdown
...

Closes #123
```

I (@dlg1206) will do my best to address the changes in a semi-timely matter.

## Document your changes

Please ensure your changes are documented with the appriate docstrings and 
any updates to the readme if needed.

[1] Adapted from https://github.com/anchore/grype/blob/main/CONTRIBUTING.md
