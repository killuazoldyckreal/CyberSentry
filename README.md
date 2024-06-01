# CyberSentry

**CyberSentry** is a powerful Discord bot designed to enhance your online safety by scanning URLs, IP addresses, and files for potential threats using the VirusTotal API. Effortlessly check links and files directly within your server, receiving real-time alerts and comprehensive threat analysis.

## Features

- **URL Scanning**: Quickly scan any URL for potential threats.
- **IP Scanning**: Check the safety of IP addresses.
- **File Scanning**: Upload files to scan for malware and other threats.
- **Rate Limit Handling**: Notifies users about API rate limits and cooldown periods.

## Commands

- `!scanurl <url>`: Scan a URL for threats.
- `!scanip <ip>`: Scan an IP address for threats.
- `!scanfile`: Upload a file to scan for threats.

## Getting Started

### Prerequisites

- Python 3.7 or higher
- Discord bot token
- VirusTotal API key

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/CyberSentry.git
    cd CyberSentry
    ```

2. Install the required libraries:
    ```bash
    pip install discord.py aiohttp aiofiles
    ```

3. Set up your environment variables:
    - Create a `.env` file in the root directory of the project.
    - Add your Discord bot token and VirusTotal API key:
      ```env
      DISCORD_BOT_TOKEN=your_discord_bot_token
      VIRUSTOTAL_API_KEY=your_virustotal_api_key
      ```

### Running the Bot

1. Run the bot:
    ```bash
    python bot.py
    ```

2. Invite the bot to your Discord server using the OAuth2 URL generated from the Discord Developer Portal.

## Usage

1. Use `!scanurl <url>` to scan a URL.
2. Use `!scanip <ip>` to scan an IP address.
3. Use `!scanfile` and upload a file to scan.

The bot will respond with a detailed report on the scan results.

## Example

```
!scanurl https://example.com
```

Bot response:


## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com) for their API
- [discord.py](https://discordpy.readthedocs.io/) for the Discord bot framework

## Contact

For any inquiries or support, please open an issue on the GitHub repository.

---

Stay vigilant, stay secure with **CyberSentry**!
