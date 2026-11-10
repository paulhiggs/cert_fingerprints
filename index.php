<?php
declare(strict_types=1);

/**
 * index.php
 *
 * All functionality lives in dvbi_securitypolicy.php.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026, Paul Higgs. See the LICENSE file.
 */

// Must stay at global scope: the CLI code in the target file reads $argv.
require __DIR__ . '/dvbi_securitypolicy.php';