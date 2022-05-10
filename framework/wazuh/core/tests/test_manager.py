#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch
from datetime import timezone, datetime

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.manager import *
        from wazuh.core.exception import WazuhException

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'manager')
ossec_log_path = '{0}/ossec_log.log'.format(test_data_path)


class InitManager:
    def __init__(self):
        """Sets up necessary environment to test manager functions"""
        # path for temporary API files
        self.api_tmp_path = os.path.join(test_data_path, 'tmp')
        # rules
        self.input_rules_file = 'test_rules.xml'
        self.output_rules_file = 'uploaded_test_rules.xml'
        # decoders
        self.input_decoders_file = 'test_decoders.xml'
        self.output_decoders_file = 'uploaded_test_decoders.xml'
        # CDB lists
        self.input_lists_file = 'test_lists'
        self.output_lists_file = 'uploaded_test_lists'


@pytest.fixture(scope='module')
def test_manager():
    # Set up
    test_manager = InitManager()
    return test_manager


def get_logs():
    with open(ossec_log_path) as f:
        return f.read()


@pytest.mark.parametrize('process_status', [
    'running',
    'stopped',
    'failed',
    'restarting',
    'starting'
])
@patch('os.path.exists')
@patch('wazuh.core.cluster.utils.glob')
def test_get_status(manager_glob, manager_exists, test_manager, process_status):
    """Tests core.manager.status()

    Tests manager.status() function in two cases:
        * PID files are created and processed are running,
        * No process is running and therefore no PID files have been created

    Parameters
    ----------
    manager_glob : mock
        Mock of glob.glob function.
    manager_exists : mock
        Mock of os.path.exists function.
    process_status : str
        Status to test (valid values: running/stopped/failed/restarting).
    """

    def mock_glob(path_to_check):
        return [path_to_check.replace('*', '0234')] if process_status == 'running' else []

    def mock_exists(path_to_check):
        if path_to_check == '/proc/0234':
            return process_status == 'running'
        else:
            return path_to_check.endswith(f'.{process_status.replace("ing", "").replace("re", "")}') or \
                   path_to_check.endswith(f'.{process_status.replace("ing", "")}')

    manager_glob.side_effect = mock_glob
    manager_exists.side_effect = mock_exists
    manager_status = status()
    assert isinstance(manager_status, dict)
    assert all(process_status == x for x in manager_status.values())
    if process_status == 'running':
        manager_exists.assert_any_call("/proc/0234")


def test_get_ossec_log_fields():
    """Test get_ossec_log_fields() method returns a tuple"""
    result = get_ossec_log_fields('2020/07/14 06:10:40 rootcheck: INFO: Ending rootcheck scan.')
    assert isinstance(result, tuple), 'The result is not a tuple'
    assert result[0] == datetime(2020, 7, 14, 6, 10, 40, tzinfo=timezone.utc)
    assert result[1] == 'wazuh-rootcheck'
    assert result[2] == 'info'
    assert result[3] == ' Ending rootcheck scan.'


def test_get_ossec_log_fields_ko():
    """Test get_ossec_log_fields() method returns None when nothing matches """
    result = get_ossec_log_fields('DEBUG')
    assert not result


def test_get_ossec_logs():
    """Test get_ossec_logs() method returns result with expected information"""
    logs = get_logs().splitlines()

    with patch('wazuh.core.manager.tail', return_value=logs):
        result = get_ossec_logs()
        assert all(key in log for key in ('timestamp', 'tag', 'level', 'description') for log in result)


def test_get_logs_summary():
    """Test get_logs_summary() method returns result with expected information"""
    logs = get_logs().splitlines()
    with patch('wazuh.core.manager.tail', return_value=logs):
        result = get_logs_summary()
        assert all(key in log for key in ('all', 'info', 'error', 'critical', 'warning', 'debug')
                   for log in result.values())
        assert result['wazuh-modulesd:database'] == {'all': 2, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0,
                                                     'debug': 2}


@patch('wazuh.core.manager.exists', return_value=True)
@patch('wazuh.core.manager.WazuhSocket')
def test_validate_ossec_conf(mock_wazuhsocket, mock_exists):
    with patch('socket.socket') as sock:
        # Mock sock response
        json_response = json.dumps({'error': 0, 'message': ""}).encode()
        mock_wazuhsocket.return_value.receive.return_value = json_response
        result = validate_ossec_conf()

        assert result == {'status': 'OK'}
        mock_exists.assert_called_with(os.path.join(common.WAZUH_PATH, 'queue', 'sockets', 'com'))


@patch("wazuh.core.manager.exists", return_value=True)
def test_validation_ko(mock_exists):
    # Daemon status check
    with pytest.raises(WazuhError, match='.* 1017 .*'):
        validate_ossec_conf()

    with patch('wazuh.core.manager.check_wazuh_status'):
        # Socket creation raise socket.error
        with patch('socket.socket', side_effect=socket.error):
            with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                validate_ossec_conf()

        with patch('socket.socket.bind'):
            # Socket connection raise socket.error
            with patch('socket.socket.connect', side_effect=socket.error):
                with pytest.raises(WazuhInternalError, match='.* 1013 .*'):
                    validate_ossec_conf()

            # execq_socket_path not exists
            with patch("wazuh.core.manager.exists", return_value=False):
                with pytest.raises(WazuhInternalError, match='.* 1901 .*'):
                    validate_ossec_conf()

            with patch('socket.socket.connect'):
                # Socket send raise socket.error
                with patch('wazuh.core.manager.WazuhSocket.send', side_effect=socket.error):
                    with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                        validate_ossec_conf()

                with patch('socket.socket.send'):
                    # Socket recv raise socket.error
                    with patch('wazuh.core.manager.WazuhSocket.receive', side_effect=socket.timeout):
                        with pytest.raises(WazuhInternalError, match='.* 1014 .*'):
                            validate_ossec_conf()

                    # _parse_execd_output raise KeyError
                    with patch('wazuh.core.manager.WazuhSocket'):
                        with patch('wazuh.core.manager.parse_execd_output', side_effect=KeyError):
                            with pytest.raises(WazuhInternalError, match='.* 1904 .*'):
                                validate_ossec_conf()


@pytest.mark.parametrize('error_flag, error_msg', [
    (0, ""),
    (1, "2019/02/27 11:30:07 wazuh-clusterd: ERROR: [Cluster] [Main] Error 3004 - Error in cluster configuration: "
        "Unspecified key"),
    (1, "2019/02/27 11:30:24 wazuh-authd: ERROR: (1230): Invalid element in the configuration: "
        "'use_source_i'.\n2019/02/27 11:30:24 wazuh-authd: ERROR: (1202): Configuration error at "
        "'/var/ossec/etc/ossec.conf'.")
])
def test_parse_execd_output(error_flag, error_msg):
    """Test parse_execd_output function works and returns expected message.

    Parameters
    ----------
    error_flag : int
        Indicate if there is an error found.
    error_msg
        Error message to be sent.
    """
    json_response = json.dumps({'error': error_flag, 'message': error_msg}).encode()
    if not error_flag:
        result = parse_execd_output(json_response)
        assert result['status'] == 'OK'
    else:
        with pytest.raises(WazuhException, match=f'.* 1908 .*'):
            parse_execd_output(json_response)


@patch('wazuh.core.manager.configuration.api_conf', new={'experimental_features': True})
def test_get_api_config():
    """Checks that get_api_config method is returning current api_conf dict."""
    result = get_api_conf()
    assert result == {'experimental_features': True}

# TODO Adapt these tests
# @pytest.mark.parametrize('api_request', [
#     agent.get_agents_summary_status,
#     wazuh.core.manager.status
# ])
# @patch('wazuh.core.manager.get_manager_status', return_value={process: 'running' for process in get_manager_status()})
# def test_DistributedAPI_check_wazuh_status(status_mock, api_request):
#     """Test `check_wazuh_status` method from class DistributedAPI."""
#     dapi = DistributedAPI(f=api_request, logger=logger)
#     data = dapi.check_wazuh_status()
#     assert data is None
#
#
# @pytest.mark.parametrize('status_value', [
#     'failed',
#     'restarting',
#     'stopped'
# ])
# @patch('wazuh.core.cluster.cluster.get_node', return_value={'node': 'random_node'})
# def test_DistributedAPI_check_wazuh_status_exception(node_info_mock, status_value):
#     """Test exceptions from `check_wazuh_status` method from class DistributedAPI."""
#     statuses = {process: status_value for process in sorted(get_manager_status())}
#     with patch('wazuh.core.manager.get_manager_status',
#                return_value=statuses):
#         dapi = DistributedAPI(f=agent.get_agents_summary_status, logger=logger)
#         try:
#             dapi.check_wazuh_status()
#         except WazuhError as e:
#             assert e.code == 1017
#             assert statuses
#             assert e._extra_message['node_name'] == 'random_node'
#             extra_message = ', '.join([f'{key}->{statuses[key]}' for key in dapi.basic_services if key in statuses])
#             assert e._extra_message['not_ready_daemons'] == extra_message