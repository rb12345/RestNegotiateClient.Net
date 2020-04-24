using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using System.Net.Http;
using System.Net.Http.Headers;

using Kerberos.NET;
using Kerberos.NET.Asn1;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace RestNegotiateClient
{
    class Program
    {
        static ILogger logger;
        static ILoggerFactory loggerFactory;
        static async Task Main(string[] args)
        {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddFilter("Microsoft", LogLevel.Warning)
                    .AddFilter("System", LogLevel.Warning)
                    .AddFilter("RestNegotiateClient.Program", LogLevel.Debug)
                    .AddFilter("Kerberos.Net", LogLevel.Trace)
                    .AddConsole(delegate(ConsoleLoggerOptions d) {  });
            });
            logger = loggerFactory.CreateLogger<Program>();
            /*CommandLineArguments parsedArgs = new CommandLineArguments(args);
            String url = (String) parsedArgs.GetValueOrDefault("");
            if (!parsedArgs.ContainsKey("keytab")) {
                await Console.Error.WriteLineAsync("Syntax: RestNegotiateClient --keytab <keytab> --principal <principal> <url>");
                return;
            }
            String keytab = (String) parsedArgs.GetValueOrDefault("keytab", "krb5.keytab");
            String principal = (String) parsedArgs.GetValueOrDefault("principal", "cud/hostname.it.ox.ac.uk@OX.AC.UK");*/
            String keytab = args[0];
            String principal = args[1];
            String url = args[2];
            String outfile = args[3];
            Console.Error.WriteLine("keytab={0}, principal={1}, url={2}", keytab, principal, url, outfile);

            // Check URL is syntactically valid
            Uri uri = null;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri)) {
                throw new ArgumentException(String.Format("Invalid URL: {0}", url));
            }

            var client = new KerberosClient("kdc0.ox.ac.uk", loggerFactory);
            client.AuthenticationOptions ^= AuthenticationOptions.Canonicalize;
            var udp = client.Transports.OfType<UdpKerberosTransport>().FirstOrDefault();
            udp.Enabled = true;
            var keyTable = new KeyTable(File.ReadAllBytes(keytab));
            var kerbCred = new KeytabCredential(principal, keyTable, "OX.AC.UK");
            logger.LogDebug("User name: {0}", kerbCred.UserName);
            await client.Authenticate(kerbCred);
            logger.LogDebug("Authenticated!");

            // Now get a service ticket for the HTTP server and perform the request
            String serverPrincipal = String.Format("HTTP/{0}", uri.DnsSafeHost);
            var ticket = await client.GetServiceTicket(serverPrincipal);
            String spnego = Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Negotiate", spnego);
            using (var outStream = File.Open(outfile, FileMode.Create)) {
                var httpStream = await httpClient.GetStreamAsync(uri);
                await httpStream.CopyToAsync(outStream);
            }
        }
    }
}
