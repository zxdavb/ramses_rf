#!/usr/bin/env python3
"""Simple test script to get a fan parameter from a Ramses device."""

import asyncio
import logging
import sys
from typing import Optional, Dict, Any

from ramses_rf import Gateway
from ramses_tx.const import Code

# Configuration
MQTT_URL = "mqtt://esp1:j%40diebla@192.168.0.84:1883"
HGI_id = "18:149488"
SOURCE_DEVICE_ID = "37:168270"  # DIS device
FAN_DEVICE_ID = "32:153289"    # FAN device
PARAMETER_ID = "75"           # Parameter ID to read
REQUEST_TIMEOUT = 10           # Seconds to wait for a response

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
_LOGGER = logging.getLogger(__name__)

# Known devices - include the HGI device
KNOWN_DEVICES = {
    HGI_id: {'class': 'HGI'},  # Gateway
    SOURCE_DEVICE_ID: {"class": "DIS", "faked": True},
    FAN_DEVICE_ID: {"class": "FAN"}
}

class FanParamTest:
    def __init__(self):
        self.gwy = None
        self.response_event = asyncio.Event()
        self.response = None
        self._remove_handler = None
    
    async def setup(self):
        """Set up the test environment."""
        _LOGGER.info("Initializing gateway...")
        
        # Create Gateway with MQTT transport
        self.gwy = Gateway(
            port_name=MQTT_URL,
            known_list=KNOWN_DEVICES,
            loop=asyncio.get_event_loop(),
            config={
                "enforce_known_list": True,
                "enforce_keepalives": False,
                "max_retries": 1,
                "restart_limit": 1,
                "reduce_processing": False,
                "enable_eavesdrop": True,
                "mqtt_client_id": "ramses_test"
            },
        )
        
        # Start the gateway first
        _LOGGER.debug("Starting gateway...")
        await self.gwy.start()
        
        # Add our message handler using the Gateway's add_msg_handler
        _LOGGER.debug("Adding message handler...")
        self.gwy.add_msg_handler(self.handle_message)
        
        # Store the message callback for cleanup
        self._msg_callback = self.gwy._protocol._msg_handler
        self._original_callback = self.gwy._protocol._msg_handler
        
        # Monkey patch the protocol's message handler to also call our handler
        async def patched_handler(msg):
            # Call the original handler first
            if asyncio.iscoroutinefunction(self._original_callback):
                await self._original_callback(msg)
            else:
                self._original_callback(msg)
            
            # Then call our handler
            self.handle_message(msg)
            
        self.gwy._protocol._msg_handler = patched_handler
        
        _LOGGER.debug("Message handler registered")
    
    async def cleanup(self):
        """Clean up resources."""
        _LOGGER.info("Cleaning up test resources...")
        
        # Restore the original message handler if we patched it
        if hasattr(self, 'gwy') and hasattr(self, '_original_callback'):
            if hasattr(self.gwy, '_protocol') and hasattr(self.gwy._protocol, '_msg_handler'):
                self.gwy._protocol._msg_handler = self._original_callback
        
        # Stop the gateway
        if hasattr(self, 'gwy') and self.gwy:
            _LOGGER.debug("Stopping gateway...")
            try:
                await self.gwy.stop()
            except Exception as e:
                _LOGGER.warning("Error stopping gateway: %s", e)
        
        _LOGGER.info("Cleanup complete")
    
    def handle_message(self, msg):
        """Handle incoming messages."""
        try:
            # Log the raw message first
            _LOGGER.debug("[HANDLER] Raw message received: %s", str(msg))
            
            # Get message attributes safely with fallbacks
            msg_dict = {}
            if hasattr(msg, 'to_dict'):
                msg_dict = msg.to_dict()
            elif hasattr(msg, '__dict__'):
                msg_dict = vars(msg)
            
            # Extract message attributes with fallbacks
            msg_code = getattr(msg, 'code', msg_dict.get('code'))
            msg_verb = getattr(msg, 'verb', msg_dict.get('verb', ''))
            msg_src = str(getattr(msg, 'src', msg_dict.get('src', '')))
            msg_dst = str(getattr(msg, 'dst', msg_dict.get('dst', '')))
            
            # Extract payload safely
            msg_payload = None
            if hasattr(msg, 'payload') and msg.payload is not None:
                msg_payload = msg.payload
            elif 'payload' in msg_dict and msg_dict['payload'] is not None:
                msg_payload = msg_dict['payload']
                
            # Get payload as hex string
            payload_hex = ''
            if msg_payload is not None:
                if isinstance(msg_payload, (bytes, bytearray)):
                    payload_hex = msg_payload.hex()
                elif isinstance(msg_payload, str):
                    # If it's already a hex string, use it directly
                    if all(c in '0123456789ABCDEFabcdef' for c in msg_payload):
                        payload_hex = msg_payload.upper()
                    else:
                        # Otherwise, treat it as a regular string and encode to hex
                        payload_hex = msg_payload.encode('utf-8').hex().upper()
                else:
                    # For other types, try to convert to string and then to hex
                    payload_hex = str(msg_payload).encode('utf-8').hex().upper()
            
            # Log all received messages at debug level
            _LOGGER.debug(
                "[MSG] Received: %s -> %s | %s %s | Payload: %s | Raw: %s",
                msg_src, 
                msg_dst,
                msg_verb,
                f"{msg_code!r}",
                payload_hex,
                str(msg)
            )
            
            # Check if this is the response we're waiting for
            if str(msg_code) == '2411' and msg_verb == 'RP':
                _LOGGER.debug("[HANDLER] Found 2411 RP message from %s", msg_src)
                
                if msg_src == FAN_DEVICE_ID:
                    _LOGGER.debug("[HANDLER] Message is from target fan device")
                    
                    if not payload_hex:
                        _LOGGER.warning("[HANDLER] Empty payload in 2411 RP message")
                        return
                        
                    _LOGGER.debug("[HANDLER] Processing payload: %s", payload_hex)
                    
                    try:
                        # Log basic message info for debugging
                        _LOGGER.debug("Received message from %s: %s", msg_src, msg)
                        
                        # Get the raw packet payload if available
                        raw_payload = ''
                        if hasattr(msg, '_pkt') and hasattr(msg._pkt, '_payload'):
                            if hasattr(msg._pkt._payload, '_hex'):
                                raw_payload = msg._pkt._payload._hex
                                _LOGGER.debug("Raw packet payload (hex): %s", raw_payload)
                        
                        # The payload is already parsed into a dictionary by ramses_rf
                        payload = msg.payload if hasattr(msg, 'payload') else {}
                        
                        # Extract the relevant information
                        param_info = {
                            'parameter': str(payload.get('parameter', '')).zfill(6) if 'parameter' in payload else '000000',
                            'description': payload.get('description', ''),
                            'value': payload.get('value'),
                            'min_value': payload.get('min_value'),
                            'max_value': payload.get('max_value'),
                            'precision': payload.get('precision'),
                            'raw_payload': raw_payload,
                            'source': msg_src,
                            'destination': msg_dst,
                            'verb': getattr(msg, 'verb', ''),
                            'code': getattr(msg, 'code', '')
                        }
                        
                        _LOGGER.debug(
                            "Extracted parameter: %s = %s (min: %s, max: %s, prec: %s)",
                            param_info['parameter'],
                            param_info['value'],
                            param_info['min_value'],
                            param_info['max_value'],
                            param_info['precision']
                        )
                        
                        # Store the response
                        self.response = param_info
                        self.response_event.set()
                    
                    except Exception as e:
                        _LOGGER.exception("[HANDLER] Error parsing payload: %s", e)
                        return
                    
                else:
                    _LOGGER.debug(
                        "[HANDLER] Ignoring 2411 RP from non-target device: %s (expected: %s)",
                        msg_src, FAN_DEVICE_ID
                    )
        except Exception as e:
            _LOGGER.exception("[HANDLER] Error processing message: %s", e)
                
        except Exception as e:
            _LOGGER.error("Error handling message %s: %s", msg, e, exc_info=True)
            # Still set the event to avoid hanging on error
            self.response = {'error': str(e)}
            self.response_event.set()
    
    async def get_fan_parameter(self):
        """Send a get_fan_param command and return the response."""
        _LOGGER.info("Starting get_fan_parameter for parameter %s", PARAMETER_ID)
        
        # Reset the event and response
        self.response_event.clear()
        self.response = None
        
        # Validate gateway is ready
        if not self.gwy or not hasattr(self.gwy, 'create_cmd'):
            error_msg = "Gateway not properly initialized"
            _LOGGER.error(error_msg)
            return {'error': error_msg}
        
        # Create and send the command using the Command.get_fan_param method
        try:
            from ramses_tx.command import Command
            _LOGGER.debug("Creating command for fan_id=%s, param_id=%s", FAN_DEVICE_ID, PARAMETER_ID)
            
            cmd = Command.get_fan_param(
                fan_id=FAN_DEVICE_ID,
                param_id=PARAMETER_ID,
                src_id=SOURCE_DEVICE_ID
            )   
            
            if not cmd:
                error_msg = "Failed to create command - create_cmd returned None"
                _LOGGER.error(error_msg)
                return {'error': error_msg}
            
            _LOGGER.debug("Sending command: %s", cmd)
            
            try:
                await self.gwy.async_send_cmd(cmd)
                _LOGGER.debug("Command sent, waiting for response...")
            except Exception as send_err:
                _LOGGER.error("Failed to send command: %s", send_err, exc_info=True)
                return {'error': f'Failed to send command: {send_err}'}
            
            # Wait for the response with a timeout
            try:
                _LOGGER.debug("Waiting for response (timeout: %ss)...", REQUEST_TIMEOUT)
                await asyncio.wait_for(self.response_event.wait(), timeout=REQUEST_TIMEOUT)
                
                if not self.response:
                    _LOGGER.warning("Response event was set but no response data is available")
                    return {'error': 'No response data available'}
                
                _LOGGER.info("Received parameter response")
                return self.response
                
            except asyncio.TimeoutError:
                _LOGGER.warning("Timed out waiting for response to parameter %s", PARAMETER_ID)
                return {'error': f'Timed out waiting for response to parameter {PARAMETER_ID}'}
            
        except Exception as e:
            _LOGGER.error("Unexpected error in get_fan_parameter: %s", e, exc_info=True)
            return {'error': f'Unexpected error in get_fan_parameter: {e}'}

async def main():
    """Main test function."""
    test = FanParamTest()
    exit_code = 1  # Default to error
    
    try:
        _LOGGER.info("Starting fan parameter test...")
        
        # Setup the test environment
        try:
            await test.setup()
            _LOGGER.info("Test environment setup complete")
        except Exception as e:
            _LOGGER.error("Failed to setup test environment: %s", e, exc_info=True)
            return 1
        
        try:
            # Log connected devices
            if hasattr(test, 'gwy') and test.gwy and hasattr(test.gwy, 'device_by_id'):
                _LOGGER.info("Connected devices:")
                for dev_id, device in test.gwy.device_by_id.items():
                    _LOGGER.info("  - %s: %s", dev_id, device.__class__.__name__)
            else:
                _LOGGER.warning("Could not list connected devices: Gateway not available")
            
            # Get the fan parameter
            _LOGGER.info("Initiating fan parameter request...")
            response = await test.get_fan_parameter()
            
            if response and 'error' not in response:
                _LOGGER.info("Successfully retrieved parameter %s: %s", 
                            response.get('parameter'), response.get('value'))
                exit_code = 0  # Success
            else:
                error_msg = response.get('error', 'Unknown error') if isinstance(response, dict) else 'No response received'
                _LOGGER.error("Failed to get fan parameter: %s", error_msg)
                exit_code = 1
                
        except asyncio.CancelledError:
            _LOGGER.warning("Test was cancelled")
            exit_code = 130  # SIGINT
        except Exception as e:
            _LOGGER.exception("Error during test execution")
            exit_code = 1
            
    except Exception as e:
        _LOGGER.exception("Unexpected error in test execution")
        exit_code = 1
        
    finally:
        try:
            _LOGGER.info("Cleaning up test resources...")
            await test.cleanup()
            _LOGGER.info("Cleanup complete")
        except Exception as e:
            _LOGGER.error("Error during cleanup: %s", e, exc_info=True)
            exit_code = 1
    
    return exit_code

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
