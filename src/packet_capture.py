#!/usr/bin/env python3
"""
WiFi Traffic Monitoring System - Packet Capture Module
"""

import logging
import threading
import time
import json
from datetime import datetime
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from pymongo import MongoClient
from urllib.parse import urlparse
import re
import hashlib

class PacketCapture:
    def __init__(self, interface='wlan0', mongodb_uri='mongodb://localhost:27017/', db_name='traffic_monitor'):
        self.interface = interface
        self.mongodb_uri = mongodb_uri
        self.db_name = db_name
        self.client = None
        self.db = None
        self.collection = None
        self.is_running = False
        self.capture_thread = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('packet_capture.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize MongoDB connection
        self.init_mongodb()
        
    def init_mongodb(self):
        """Initialize MongoDB connection"""
        try:
            self.client = MongoClient(self.mongodb_uri)
            self.db = self.client[self.db_name]
            self.collection = self.db.packets
            
            # Create indexes for better performance
            self.collection.create_index([('timestamp', -1)])
            self.collection.create_index([('src_ip', 1)])
            self.collection.create_index([('dest_ip', 1)])
            self.collection.create_index([('protocol', 1)])
            
            self.logger.info("MongoDB connection established successfully")
            
        except Exception as e:
            self.logger.error(f"MongoDB connection failed: {e}")
            raise
    
    def extract_url_from_http(self, packet):
        """Extract URL from HTTP packets"""
        try:
            if packet.haslayer(HTTPRequest):
                host = packet[HTTPRequest].Host.decode('utf-8') if packet[HTTPRequest].Host else ""
                path = packet[HTTPRequest].Path.decode('utf-8') if packet[HTTPRequest].Path else ""
                return f"http://{host}{path}"
        except Exception as e:
            self.logger.debug(f"Error extracting URL: {e}")
        return None
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': None,
                'dest_ip': None,
                'src_port': None,
                'dest_port': None,
                'protocol': None,
                'packet_length': len(packet),
                'url': None,
                'packet_id': hashlib.md5(str(packet).encode()).hexdigest()[:16]
            }
            
            # Extract IP layer info
            if packet.haslayer(IP):
                packet_info['src_ip'] = packet[IP].src
                packet_info['dest_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto
                
                # Map protocol numbers to names
                protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                packet_info['protocol'] = protocol_map.get(packet[IP].proto, str(packet[IP].proto))
            
            # Extract port info
            if packet.haslayer(TCP):
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dest_port'] = packet[TCP].dport
                packet_info['protocol'] = 'TCP'
            elif packet.haslayer(UDP):
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dest_port'] = packet[UDP].dport
                packet_info['protocol'] = 'UDP'
            
            # Extract URL for HTTP traffic
            if packet.haslayer(HTTPRequest):
                packet_info['url'] = self.extract_url_from_http(packet)
            
            # Extract DNS queries
            if packet.haslayer(DNS) and packet[DNS].qd:
                packet_info['dns_query'] = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def save_packet_to_db(self, packet_info):
        """Save packet information to MongoDB"""
        try:
            if packet_info:
                self.collection.insert_one(packet_info)
                self.logger.debug(f"Saved packet: {packet_info['packet_id']}")
        except Exception as e:
            self.logger.error(f"Error saving packet to database: {e}")
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        packet_info = self.extract_packet_info(packet)
        if packet_info:
            self.save_packet_to_db(packet_info)
    
    def start_capture(self):
        """Start packet capture"""
        if self.is_running:
            self.logger.warning("Capture is already running")
            return
            
        self.is_running = True
        self.logger.info(f"Starting packet capture on interface: {self.interface}")
        
        def capture_loop():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    store=0,
                    stop_filter=lambda p: not self.is_running
                )
            except Exception as e:
                self.logger.error(f"Error in capture loop: {e}")
                self.is_running = False
        
        self.capture_thread = threading.Thread(target=capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self.logger.info("Packet capture started successfully")
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_running:
            self.logger.warning("Capture is not running")
            return
            
        self.is_running = False
        self.logger.info("Stopping packet capture...")
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        
        self.logger.info("Packet capture stopped")
    
    def get_capture_stats(self):
        """Get capture statistics"""
        try:
            total_packets = self.collection.count_documents({})
            protocols = self.collection.distinct('protocol')
            
            # Get recent activity (last 1 hour)
            one_hour_ago = datetime.now() - timedelta(hours=1)
            recent_packets = self.collection.count_documents({
                'timestamp': {'$gte': one_hour_ago.isoformat()}
            })
            
            return {
                'total_packets': total_packets,
                'protocols': protocols,
                'recent_packets': recent_packets,
                'is_running': self.is_running
            }
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return {}
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_capture()
        if self.client:
            self.client.close()
        self.logger.info("Cleanup completed")

if __name__ == "__main__":
    # Command line interface
    import argparse
    
    parser = argparse.ArgumentParser(description='WiFi Traffic Packet Capture')
    parser.add_argument('-i', '--interface', default='wlan0', help='Network interface to capture from')
    parser.add_argument('-d', '--duration', type=int, help='Capture duration in seconds')
    parser.add_argument('--mongodb-uri', default='mongodb://localhost:27017/', help='MongoDB connection URI')
    parser.add_argument('--db-name', default='traffic_monitor', help='Database name')
    
    args = parser.parse_args()
    
    # Initialize packet capture
    capture = PacketCapture(
        interface=args.interface,
        mongodb_uri=args.mongodb_uri,
        db_name=args.db_name
    )
    
    try:
        capture.start_capture()
        
        if args.duration:
            time.sleep(args.duration)
            capture.stop_capture()
        else:
            # Run indefinitely
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        print("\nReceived interrupt signal, stopping...")
        capture.cleanup()
    except Exception as e:
        print(f"Error: {e}")
        capture.cleanup()
