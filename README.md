# 🕷️ Cyber Hunter - Cybersecurity Job Spider

Automated OSINT tool for hunting cybersecurity job positions. Scrapes Greenhouse and Lever job boards used by top security companies.

## 🎯 Features

- **Multi-platform support**: Greenhouse, Lever (extensible to others)
- **Smart filtering**: Only relevant cybersecurity roles
- **Entry-level detection**: Flags intern/junior positions
- **Remote job flagging**: Identifies remote opportunities  
- **Discord notifications**: Get pinged when new intern roles appear
- **Cloud-ready**: Optimized for Zyte's free tier

## 🚀 Quick Start

### Local Testing

```bash
# Run the spider locally
cd cyber_hunter
scrapy crawl cyber_jobs -o output/jobs.json

# Or output as CSV
scrapy crawl cyber_jobs -o output/jobs.csv
```

### Deploy to Zyte Cloud

1. **Login to Zyte CLI** (get API key from [Zyte Dashboard](https://app.zyte.com) → User Settings → API Key):
   ```bash
   shub login
   # Paste your API key when prompted
   ```

2. **Update project ID** in `scrapy.cfg` and `scrapinghub.yml`:
   ```yaml
   project: YOUR_PROJECT_ID  # Find this in your Zyte dashboard URL
   ```

3. **Deploy**:
   ```bash
   shub deploy
   ```

4. **Schedule** (Zyte Dashboard → Periodic Jobs):
   - Spider: `cyber_jobs`
   - Schedule: Daily at 08:00 AM

## 🔔 Discord Notifications (Optional)

Get instant alerts when intern/entry-level positions are found!

1. Create a webhook in your Discord server:
   - Server Settings → Integrations → Webhooks → New Webhook
   - Copy the webhook URL

2. Enable in `settings.py`:
   ```python
   DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
   
   ITEM_PIPELINES = {
       "cyber_hunter.pipelines.CyberJobPipeline": 300,
       "cyber_hunter.pipelines.DiscordNotificationPipeline": 400,  # Uncomment this
   }
   ```

3. Configure notification preferences:
   ```python
   DISCORD_NOTIFY_INTERNS_ONLY = True  # Only ping for intern/entry-level roles
   ```

## 📋 Adding More Companies

Edit `cyber_hunter/spiders/job_spider.py` and add URLs to `start_urls`:

```python
start_urls = [
    # Greenhouse boards
    'https://boards.greenhouse.io/COMPANY_NAME',
    
    # Lever boards  
    'https://jobs.lever.co/COMPANY_NAME',
]
```

**Pro Tip**: When you find an interesting job posting, check the URL to identify which platform they use!

## 🔧 Customizing Filters

Modify keyword lists in `job_spider.py`:

```python
# Jobs must contain at least one of these
POSITIVE_KEYWORDS = ['security', 'cyber', 'pentest', 'intern', ...]

# These jobs will be excluded
EXCLUDE_KEYWORDS = ['sales', 'marketing', 'recruiter', ...]

# Optional: Uncomment filter to exclude senior roles
SENIOR_KEYWORDS = ['senior', 'manager', 'director', ...]
```

## 📊 Output Format

```json
{
    "company": "CrowdStrike",
    "title": "Security Analyst Intern - Summer 2025",
    "location": "Austin, TX",
    "url": "https://boards.greenhouse.io/crowdstrike/jobs/123456",
    "platform": "Greenhouse",
    "scraped_at": "2025-12-02T08:00:00Z",
    "is_intern": true,
    "is_remote": false
}
```

## 🛡️ Why This is a Cybersecurity Project

| Skill | Application |
|-------|-------------|
| **Recon** | Enumerating endpoints (job URLs) |
| **Filtering** | Logic-based noise reduction (like SIEM log filtering) |
| **Automation** | Automating an OSINT task |
| **Data Pipeline** | ETL from multiple sources |

## 📁 Project Structure

```
cyber_hunter/
├── scrapy.cfg              # Scrapy configuration
├── scrapinghub.yml         # Zyte deployment config
├── requirements.txt        # Python dependencies
├── output/                 # Scraped job data
└── cyber_hunter/
    ├── __init__.py
    ├── items.py            # Data models
    ├── middlewares.py      # Request/response processing
    ├── pipelines.py        # Data processing & Discord alerts
    ├── settings.py         # Spider configuration
    └── spiders/
        ├── __init__.py
        └── job_spider.py   # Main spider code
```

## 📜 License

MIT - Happy hunting! 🎯
