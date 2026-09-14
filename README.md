# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/basil9099/kdetect/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                     |    Stmts |     Miss |   Cover |   Missing |
|----------------------------------------- | -------: | -------: | ------: | --------: |
| src/kdetect/\_\_init\_\_.py              |        1 |        0 |    100% |           |
| src/kdetect/analysis/\_\_init\_\_.py     |        0 |        0 |    100% |           |
| src/kdetect/analysis/models.py           |       33 |        0 |    100% |           |
| src/kdetect/analysis/scoring.py          |       42 |        0 |    100% |           |
| src/kdetect/analysis/signals.py          |      103 |        2 |     98% |   90, 160 |
| src/kdetect/baseline/\_\_init\_\_.py     |        0 |        0 |    100% |           |
| src/kdetect/baseline/store.py            |       38 |        5 |     87% | 28-31, 37 |
| src/kdetect/cli.py                       |      219 |       32 |     85% |99, 114-127, 202-206, 237-238, 244-246, 255, 260-261, 295, 354-355, 364, 372, 377 |
| src/kdetect/collectors/\_\_init\_\_.py   |        0 |        0 |    100% |           |
| src/kdetect/collectors/base.py           |       29 |        0 |    100% |           |
| src/kdetect/collectors/kernel\_hooks.py  |       29 |        1 |     97% |        46 |
| src/kdetect/collectors/modules.py        |       30 |        0 |    100% |           |
| src/kdetect/collectors/procfs.py         |       65 |       11 |     83% |28, 31-33, 59-62, 87-93 |
| src/kdetect/collectors/sockets.py        |       34 |        0 |    100% |           |
| src/kdetect/collectors/sources.py        |      218 |       16 |     93% |46, 63-64, 125, 135, 145-146, 176-177, 230, 238, 278, 293-294, 322-323 |
| src/kdetect/collectors/syscall\_sweep.py |       21 |        0 |    100% |           |
| src/kdetect/hostfacts.py                 |       17 |        1 |     94% |        30 |
| src/kdetect/models.py                    |      184 |        0 |    100% |           |
| src/kdetect/parsers/\_\_init\_\_.py      |        0 |        0 |    100% |           |
| src/kdetect/parsers/kernel\_hooks.py     |       72 |        2 |     97% |   80, 103 |
| src/kdetect/parsers/modules.py           |       43 |        1 |     98% |        31 |
| src/kdetect/parsers/procfs.py            |       46 |        5 |     89% |51, 61-62, 106-109 |
| src/kdetect/parsers/sockets.py           |       39 |        3 |     92% | 52, 72-73 |
| src/kdetect/reporting/\_\_init\_\_.py    |        0 |        0 |    100% |           |
| src/kdetect/reporting/escape.py          |       37 |        1 |     97% |        35 |
| src/kdetect/reporting/iocs.py            |       46 |        0 |    100% |           |
| src/kdetect/reporting/redact.py          |        8 |        0 |    100% |           |
| src/kdetect/reporting/report.py          |       58 |        1 |     98% |        81 |
| **TOTAL**                                | **1412** |   **81** | **94%** |           |


## Setup coverage badge

Below are examples of the badges you can use in your main branch `README` file.

### Direct image

[![Coverage badge](https://raw.githubusercontent.com/basil9099/kdetect/python-coverage-comment-action-data/badge.svg)](https://htmlpreview.github.io/?https://github.com/basil9099/kdetect/blob/python-coverage-comment-action-data/htmlcov/index.html)

This is the one to use if your repository is private or if you don't want to customize anything.

### [Shields.io](https://shields.io) Json Endpoint

[![Coverage badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/basil9099/kdetect/python-coverage-comment-action-data/endpoint.json)](https://htmlpreview.github.io/?https://github.com/basil9099/kdetect/blob/python-coverage-comment-action-data/htmlcov/index.html)

Using this one will allow you to [customize](https://shields.io/endpoint) the look of your badge.
It won't work with private repositories. It won't be refreshed more than once per five minutes.

### [Shields.io](https://shields.io) Dynamic Badge

[![Coverage badge](https://img.shields.io/badge/dynamic/json?color=brightgreen&label=coverage&query=%24.message&url=https%3A%2F%2Fraw.githubusercontent.com%2Fbasil9099%2Fkdetect%2Fpython-coverage-comment-action-data%2Fendpoint.json)](https://htmlpreview.github.io/?https://github.com/basil9099/kdetect/blob/python-coverage-comment-action-data/htmlcov/index.html)

This one will always be the same color. It won't work for private repos. I'm not even sure why we included it.

## What is that?

This branch is part of the
[python-coverage-comment-action](https://github.com/marketplace/actions/python-coverage-comment)
GitHub Action. All the files in this branch are automatically generated and may be
overwritten at any moment.