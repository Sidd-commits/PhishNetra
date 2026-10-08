import { reportService } from '../src/services/ReportService';

describe('Community Threat Reports & Moderation Hub Suite', () => {
  it('should allow submitting a new threat report with pending status', async () => {
    const report = await reportService.createReport(null, 'SecurityResearcher', {
      url: 'https://fake-login-bank.com/auth',
      reportType: 'PHISHING',
      description: 'Lure email directing to credential harvest page',
      evidenceDetails: 'Form action posts to raw IP 185.220.101.5'
    });

    expect(report).toBeDefined();
    expect(report.id).toBeDefined();
    expect(report.domain).toBe('fake-login-bank.com');
    expect(report.reportType).toBe('PHISHING');
    expect(report.status).toBe('PENDING');
  });

  it('should list reports with filtering by status', async () => {
    const list = await reportService.listReports({ limit: 10 });
    expect(list.total).toBeGreaterThan(0);
    expect(Array.isArray(list.reports)).toBe(true);
  });

  it('should allow SOC analysts to moderate report status to APPROVED or REJECTED', async () => {
    const created = await reportService.createReport(null, 'User123', {
      url: 'https://phishing-campaign-sample.com/signin',
      reportType: 'CREDENTIAL_HARVEST',
      description: 'Stolen login form'
    });

    const moderated = await reportService.moderateReport(created.id, 'SOC_Lead_Analyst', {
      status: 'APPROVED',
      moderatorNotes: 'Confirmed brand impersonation and active credential logger.'
    });

    expect(moderated.status).toBe('APPROVED');
    expect(moderated.moderatedBy).toBe('SOC_Lead_Analyst');
    expect(moderated.moderatorNotes).toContain('Confirmed brand impersonation');

    // Check domain signals
    const signals = await reportService.getDomainCommunitySignals('phishing-campaign-sample.com');
    expect(signals.totalApproved).toBeGreaterThanOrEqual(1);
    expect(signals.hasConfirmedPhishing).toBe(true);
  });
});
