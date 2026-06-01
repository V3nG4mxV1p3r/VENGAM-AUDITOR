/**
 * VENGAM GameSec Auditor — GitHub Action Entry Point
 * TypeScript wrapper for the composite action steps.
 * Provides typed input/output handling and summary generation.
 */

import * as core    from '@actions/core';
import * as exec    from '@actions/exec';
import * as artifact from '@actions/artifact';
import * as fs      from 'fs';
import * as path    from 'path';

async function run(): Promise<void> {
  try {
    // ── Read inputs ─────────────────────────────────────────────
    const apkPath        = core.getInput('apk_path',        { required: true });
    const platform       = core.getInput('platform')        || 'android';
    const severityFilter = core.getInput('severity_filter') || '';
    const categoryFilter = core.getInput('category_filter') || '';
    const failOn         = core.getInput('fail_on')         || 'BLOCK_RELEASE';
    const outputDir      = core.getInput('output_dir')      || 'vengam-reports';
    const uploadSarif    = core.getInput('upload_sarif')    !== 'false';

    core.info(`VENGAM GameSec Auditor v7.0.0`);
    core.info(`Target   : ${apkPath}`);
    core.info(`Platform : ${platform}`);
    core.info(`Fail on  : ${failOn}`);

    // ── Build CLI args ───────────────────────────────────────────
    const args: string[] = [
      '-m', 'vengam.cli',
      '-t', apkPath,
      '-o', outputDir,
      '--format', 'all',
    ];

    if (platform === 'ios')      args.push('--ios');
    if (severityFilter)          args.push('--severity-filter', severityFilter);
    if (categoryFilter)          args.push('--category-filter', categoryFilter);

    // ── Run scan ─────────────────────────────────────────────────
    fs.mkdirSync(outputDir, { recursive: true });

    let exitCode = 0;
    try {
      exitCode = await exec.exec('python', args, { ignoreReturnCode: true });
    } catch (err) {
      core.warning(`Scan process error: ${err}`);
    }

    // ── Parse JSON report ────────────────────────────────────────
    const stem     = path.basename(apkPath).replace(/\.[^.]+$/, '');
    const jsonPath = path.join(outputDir, `${stem}_vengam_report.json`);
    const txtPath  = path.join(outputDir, `${stem}_vengam_report.txt`);
    const sarPath  = path.join(outputDir, `${stem}_vengam_report.sarif`);

    let riskScore     = 0;
    let verdict       = 'UNKNOWN';
    let findingsCount = 0;

    if (fs.existsSync(jsonPath)) {
      try {
        const data    = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
        riskScore     = data.risk_score     ?? 0;
        verdict       = data.verdict        ?? 'UNKNOWN';
        findingsCount = data.findings?.length ?? 0;
      } catch {
        core.warning('Could not parse JSON report.');
      }
    }

    // ── Set outputs ──────────────────────────────────────────────
    core.setOutput('risk_score',     String(riskScore));
    core.setOutput('verdict',        verdict);
    core.setOutput('findings_count', String(findingsCount));
    core.setOutput('report_txt',     txtPath);
    core.setOutput('report_json',    jsonPath);
    core.setOutput('report_sarif',   sarPath);

    // ── Job summary ──────────────────────────────────────────────
    const emoji = verdict === 'BLOCK RELEASE' ? '🔴'
                : verdict.includes('AT RISK')  ? '🟠' : '✅';

    await core.summary
      .addHeading('VENGAM GameSec Auditor')
      .addTable([
        [{ data: 'Metric',       header: true }, { data: 'Value', header: true }],
        ['Risk Score',     `${riskScore} / 100`],
        ['Verdict',        `${emoji} ${verdict}`],
        ['Findings',       String(findingsCount)],
        ['Platform',       platform.toUpperCase()],
        ['Target',         apkPath],
      ])
      .write();

    // ── Enforce fail_on policy ───────────────────────────────────
    if (failOn === 'NEVER') {
      core.info('✅ fail_on=NEVER — pipeline continues.');
      return;
    }

    if (failOn === 'BLOCK_RELEASE' && verdict === 'BLOCK RELEASE') {
      core.setFailed(`🔴 BLOCK RELEASE — Risk score: ${riskScore}/100. Halt deployment.`);
      return;
    }

    if (failOn === 'AT_RISK' && verdict !== 'CONDITIONALLY SAFE') {
      core.setFailed(`🟠 AT RISK — Risk score: ${riskScore}/100. Remediation required.`);
      return;
    }

    core.info(`✅ Verdict within acceptable threshold: ${verdict}`);

  } catch (error) {
    core.setFailed(`VENGAM action failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

run();
