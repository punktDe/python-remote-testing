"""
MIT License

Copyright (c) 2020 Lars Liedtke

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import unittest
import rpyc
import plumbum as pb
import smtplib

from email.message import EmailMessage

from rpyc.utils.zerodeploy import DeployedServer


class ExternalNetworkRestrictions(unittest.TestCase):

    def test_logged_out_smtp_expect_client_host_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="user",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()

        with connection.modules.smtplib.SMTP("mail.example.com") as smtp:
            with self.assertRaises(smtplib.SMTPRecipientsRefused) as e:
                smtp.send_message(message,
                                  from_addr="sender@example.com",
                                  to_addrs="receiver@example.com")

            self.assertIn("Client host rejected: Access denied", str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_logged_out_smtps_expect_client_host_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="user",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()

        with connection.modules.smtplib.SMTP_SSL("mail.example.com", 465) as smtp:
            with self.assertRaises(smtplib.SMTPRecipientsRefused) as e:
                smtp.send_message(message,
                                  from_addr="sender@example.com",
                                  to_addrs="receiver@example.com")
            self.assertIn("Client host rejected: Access denied", str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_logged_out_starttls_expect_client_host_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()

        with connection.modules.smtplib.SMTP("mail.example.com", 587) as smtp:
            smtp.starttls()
            with self.assertRaises(smtplib.SMTPRecipientsRefused) as e:
                smtp.send_message(message,
                                  from_addr="sender@example.com",
                                  to_addrs="receiver@example.com")
            self.assertIn("Client host rejected: Access denied", str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_smtp_login_expect_reject(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP("mail.example.com") as smtp:
            with self.assertRaises(smtplib.SMTPNotSupportedError) as e:
                smtp.login(user="user", password="test")
                smtp.send_message(message,
                                  from_addr="sender@example.com",
                                  to_addrs="receiver@example.com")
            self.assertIn("SMTP AUTH extension not supported by server", str(e.exception), msg=str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_login_username_smtps_wrong_credentials_expect_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP_SSL("mail.example.com", 465) as smtp:
            with self.assertRaises(smtplib.SMTPAuthenticationError) as e:
                smtp.login(user="user", password="test")
                smtp.send_message(message,
                                  from_addr="sender@example.com",
                                  to_addrs="receiver@example.com")
            self.assertIn("Error: authentication failed", str(e.exception), msg=str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_login_username_starttls_wrong_credentials_expect_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP("mail.example.com", 587) as smtp:
            smtp.starttls()

            with self.assertRaises(smtplib.SMTPAuthenticationError) as e:
                smtp.login(user="user", password="test")
            self.assertIn("Error: authentication failed", str(e.exception), msg=str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_login_mailaddress_smtps_wrong_credentials_expect_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP_SSL("mail.example.com",465) as smtp:
            with self.assertRaises(smtplib.SMTPAuthenticationError) as e:
                smtp.login(user="user@example.com", password="test")
            self.assertIn("Error: authentication failed", str(e.exception), msg=str(e.exception))

        connection.close()
        server.close()
        machine.close()
        
    def test_login_mailaddress_starttls_wrong_credentials_expect_rejected(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()

        with connection.modules.smtplib.SMTP("mail.example.com", 587) as smtp:
            smtp.starttls()

            with self.assertRaises(smtplib.SMTPAuthenticationError) as e:
                smtp.login(user="user@example.com", password="test")
            self.assertIn("Error: authentication failed", str(e.exception), msg=str(e.exception))

        connection.close()
        server.close()
        machine.close()

    def test_login_username_smtps_expect_pass(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP_SSL("mail.example.com", 465) as smtp:
            smtp.login(user="user", password="supersecret")

        connection.close()
        server.close()
        machine.close()

    def test_login_username_starttls_expect_pass(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP("mail.example.com", 587) as smtp:
            smtp.starttls()

            smtp.login(user="user", password="supersecret")

        connection.close()
        server.close()
        machine.close()

    def test_login_mailaddress_smtps_expect_pass(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP_SSL("mail.example.com", 465) as smtp:

            smtp.login(user="user@example.com",
                       password="supersecret")

        connection.close()
        server.close()
        machine.close()

    def test_login_mailaddress_starttls_expect_pass(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP("mail.example.com", 587) as smtp:
            smtp.starttls()

            smtp.login(user="user@example.com", password="supersecret")

        connection.close()
        server.close()
        machine.close()

    def test_logged_in_smtps_non_fqdn_helo_hostname_expect_pass(self):
        message = EmailMessage()
        message["From"] = "sender@example.com"
        message["To"] = "receiver@example.com"
        message["Subject"] = "Test"

        machine: pb.SshMachine = pb.SshMachine(host="remote.example.com", user="proserver",
                                               keyfile="~/.ssh/id_rsa")
        server = DeployedServer(machine)
        connection: rpyc.Connection = server.classic_connect()
        
        with connection.modules.smtplib.SMTP_SSL("mail.example.com", 465) as smtp:
            smtp.ehlo("test_helo")
            smtp.login(user="user", password="supersecret")
            smtp.send_message(message,
                              from_addr="sender@example.com",
                              to_addrs="receiver@example.com")

        connection.close()
        server.close()
        machine.close()
        

if __name__ == '__main__':
    unittest.main()
