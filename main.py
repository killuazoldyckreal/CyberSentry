import discord
from discord import app_commands
from discord.ext import commands
import aiohttp
import asyncio
import json
import aiofiles
import base64
import time
import os, traceback
from dotenv import load_dotenv

load_dotenv()

# Fetching Environment Variables
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

BASE_URL = 'https://www.virustotal.com/api/v3'
RATE_LIMIT = 4  # Requests per minute

class RateLimitExceededError(Exception):
    pass

class Scanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {
            'x-apikey': self.api_key
        }
        self.requests_made = 0
        self.last_reset_time = time.time()

    async def scan_url(self, session, url):
        """Scan a URL using VirusTotal."""
        await self.check_rate_limit()
        print(f"Scanning URL: {url}")
        url_id = self.url_id(url)
        async with session.get(f"{BASE_URL}/urls/{url_id}", headers=self.headers) as response:
            if response.status == 200:
                url_report = await response.json()
                return url_report['data']['attributes']['last_analysis_stats']
            else:
                return {'error': response.status}

    async def scan_ip(self, session, ip):
        """Scan an IP address using VirusTotal."""
        await self.check_rate_limit()
        print(f"Scanning IP: {ip}")
        async with session.get(f"{BASE_URL}/ip_addresses/{ip}", headers=self.headers) as response:
            if response.status == 200:
                ip_report = await response.json()
                return ip_report['data']['attributes']['last_analysis_stats']
            else:
                print(response)
                return {'error': response.status}

    async def scan_file(self, session, file_path):
        """Scan a file using VirusTotal."""
        await self.check_rate_limit()
        print(f"Scanning file: {file_path}")
        try:
            async with aiofiles.open(file_path, "rb") as file:
                data = await file.read()
                async with session.post(f"{BASE_URL}/files", headers=self.headers, data={'file': data}) as response:
                    if response.status == 200:
                        file_report = await response.json()
                        file_id = file_report['data']['id']
                        # Wait for the analysis to complete
                        await asyncio.sleep(15)
                        while True:
                            async with session.get(f"{BASE_URL}/analyses/{file_id}", headers=self.headers) as completed_response:
                                if completed_response.status == 200:
                                    completed_report = await completed_response.json()
                                    if completed_report['data']['attributes']['status']=="completed":
                                    	return completed_report['data']['attributes']['stats']
                                else:
                                    return {'error': completed_response.status}
                            await asyncio.sleep(15)
                    else:
                        return {'error': response.status}
        except FileNotFoundError:
            return {'error': 'File not found'}

    def url_id(self, url):
        """Create a URL ID for VirusTotal API."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return url_id

    async def check_rate_limit(self):
        """Ensure the API rate limit is not exceeded."""
        current_time = time.time()
        if current_time - self.last_reset_time >= 60:
            self.requests_made = 0
            self.last_reset_time = current_time

        if self.requests_made >= RATE_LIMIT:
            raise RateLimitExceededError(f"Rate limit exceeded. Please wait {60 - int(current_time - self.last_reset_time)} seconds before trying again.")
        
        self.requests_made += 1

def create_embed(author, title, stats, description):
    """Create an embed message with analysis stats."""
    embed = discord.Embed(title=title, description=description, color=0x00ff00)
    embed.set_author(name=author.name, icon_url=author.display_avatar.url)
    for key, value in list(stats.items())[:5]:
        embed.add_field(name=key, value=value, inline=False)
    return embed

class VirusTotalBot(commands.Bot):
    def __init__(self, command_prefix, api_key, *args, **kwargs):
        super().__init__(command_prefix, intents = discord.Intents.all(), help_command= None, *args, **kwargs)
        self.scanner = Scanner(api_key)

    async def on_ready(self):
        synced = await self.tree.sync()
        print(f"Synced {len(synced)} command(s)")
        print(f'Logged in as {self.user}')

bot = VirusTotalBot(command_prefix='!', api_key=API_KEY)

@bot.hybrid_command(name="help", description="Show guide to how to get started.", with_app_command = True)
async def send_bot_help(ctx: commands.Context):
    embed = discord.Embed(title="CyberSentry Help", color=0x7289da)
    embed.description = "Here are the available commands for CyberSentry:"
    embed.add_field(name="/help", value="Guide to how to get started", inline=False)
    embed.add_field(name="/scanip [ip_address]", value="Scan a IP for threats.", inline=False)
    embed.add_field(name="/scanurl [url]", value="Scan a URL for threats.", inline=False)
    embed.add_field(name="!scanfile", value="Scan a File for threats. Attach File to scan it.", inline=False)
    embed.add_field(name=" ", value="Scan file command is only available as prefix command.", inline=False)
    await ctx.send(embed=embed)
    
@bot.hybrid_command(name="scanurl", description="Scan a URL for threats.", with_app_command=True)
@app_commands.describe(url = "Enter the URL you want to scan")
async def scan_url(ctx, url: str):
    """Scan a URL."""
    await ctx.defer()
    async with aiohttp.ClientSession() as session:
        try:
            result = await bot.scanner.scan_url(session, url)
            if 'error' in result:
                await ctx.send(f"Error: {result['error']}")
                return

            description = "The URL is safe to use." if result['malicious'] == 0 else "The URL might be unsafe."
            embed = create_embed(ctx.author, "URL Scan Result", result, description)
            await ctx.send(embed=embed)
        except RateLimitExceededError as e:
            await ctx.send(str(e))

@bot.hybrid_command(name="scanip", description="Scan a IP for threats.", with_app_command=True)
@app_commands.describe(ip = "Enter the IP you want to scan")
async def scan_ip(ctx, ip):
    """Scan an IP address."""
    await ctx.defer()
    async with aiohttp.ClientSession() as session:
        try:
            result = await bot.scanner.scan_ip(session, ip)
            if 'error' in result:
                await ctx.send(f"Error: {result['error']}")
                return

            description = "The IP address is safe." if result['malicious'] == 0 else "The IP address might be unsafe."
            embed = create_embed(ctx.author, "IP Scan Result", result, description)
            await ctx.send(embed=embed)
        except RateLimitExceededError as e:
            await ctx.send(str(e))

@bot.command()
async def scanfile(ctx):
    """Scan an uploaded file."""
    if not ctx.message.attachments:
        await ctx.send("Please upload a file to scan.")
        return

    await ctx.send("Please wait while the bot scans the file...")
    attachment = ctx.message.attachments[0]
    file_path = attachment.filename
    await attachment.save(file_path)

    async with aiohttp.ClientSession() as session:
        try:
            result = await bot.scanner.scan_file(session, file_path)
            if 'error' in result:
                await ctx.send(f"Error: {result['error']}")
                return

            description = "The file is safe." if result['malicious'] == 0 else "The file might be unsafe."
            embed = create_embed(ctx.author, "File Scan Result", result, description)
            await ctx.send(embed=embed)
        except RateLimitExceededError as e:
            await ctx.send(str(e))
        finally:
            # Clean up the saved file
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error removing file: {e}")

if __name__ == "__main__":
    bot.run(BOT_TOKEN)
