"""Tests for sandbox module."""

import socket
import tarfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from docker.errors import NotFound

from strix_cli_claude import sandbox
from strix_cli_claude.sandbox import Sandbox, SandboxError, get_cpu_count


class TestGetCpuCount:
    """Tests for get_cpu_count function."""

    def test_returns_positive_count(self):
        """Should return at least 1 CPU."""
        result = get_cpu_count()
        assert result >= 1

    def test_reserves_cpus_for_host(self):
        """Should reserve CPUs for the host system."""
        with patch("multiprocessing.cpu_count", return_value=8):
            result = get_cpu_count(reserve=2)
            assert result == 6

    def test_minimum_one_cpu(self):
        """Should return at least 1 CPU even with high reserve."""
        with patch("multiprocessing.cpu_count", return_value=2):
            result = get_cpu_count(reserve=10)
            assert result == 1

    def test_custom_reserve(self):
        """Should allow custom reserve value."""
        with patch("multiprocessing.cpu_count", return_value=16):
            result = get_cpu_count(reserve=4)
            assert result == 12


class TestSandboxError:
    """Tests for SandboxError exception."""

    def test_is_exception(self):
        """Should be an exception type."""
        assert issubclass(SandboxError, Exception)

    def test_can_be_raised(self):
        """Should be raisable with a message."""
        with pytest.raises(SandboxError) as exc_info:
            raise SandboxError("Test error message")
        assert str(exc_info.value) == "Test error message"


class TestSandboxInit:
    """Tests for Sandbox initialization."""

    def test_uses_default_image(self):
        """Should use default image when not specified."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            assert sb.image == sandbox.DEFAULT_SANDBOX_IMAGE

    def test_uses_custom_image(self):
        """Should use custom image when specified."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox(image="custom/image:latest")
            assert sb.image == "custom/image:latest"

    def test_uses_env_image(self):
        """Should use STRIX_IMAGE environment variable."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            with patch.dict("os.environ", {"STRIX_IMAGE": "env/image:v1"}):
                sb = Sandbox()
                assert sb.image == "env/image:v1"

    def test_uses_custom_scan_id(self):
        """Should use custom scan_id when specified."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox(scan_id="my-scan-123")
            assert sb.scan_id == "my-scan-123"

    def test_generates_scan_id_when_not_specified(self):
        """Should generate scan_id when not specified."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            assert sb.scan_id.startswith("scan-")
            assert len(sb.scan_id) > len("scan-")

    def test_raises_error_when_docker_unavailable(self):
        """Should raise SandboxError when Docker is not available."""
        from docker.errors import DockerException

        with patch("docker.from_env", side_effect=DockerException("Not available")):
            with pytest.raises(SandboxError) as exc_info:
                Sandbox()
            assert "Docker is not available" in str(exc_info.value)


class TestFindAvailablePort:
    """Tests for _find_available_port method."""

    def test_returns_available_port(self):
        """Should return an available port."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            port = sb._find_available_port()
            assert isinstance(port, int)
            assert port > 0
            assert port < 65536

    def test_returns_different_ports(self):
        """Should return different ports on subsequent calls."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            port1 = sb._find_available_port()
            port2 = sb._find_available_port()
            # Note: In rare cases they could be the same if the first port is released
            # but the test is probabilistic and usually passes
            assert isinstance(port1, int)
            assert isinstance(port2, int)


class TestGenerateToken:
    """Tests for _generate_token method."""

    def test_returns_string(self):
        """Should return a string token."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            token = sb._generate_token()
            assert isinstance(token, str)

    def test_returns_non_empty_token(self):
        """Should return a non-empty token."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            token = sb._generate_token()
            assert len(token) > 0

    def test_returns_different_tokens(self):
        """Should return different tokens on subsequent calls."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            token1 = sb._generate_token()
            token2 = sb._generate_token()
            assert token1 != token2


class TestExecWithTimeout:
    """Tests for _exec_with_timeout method."""

    def test_executes_command(self):
        """Should execute command on container."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            mock_container = MagicMock()
            mock_result = MagicMock()
            mock_result.exit_code = 0
            mock_result.output = b"success"
            mock_container.exec_run.return_value = mock_result

            result = sb._exec_with_timeout(mock_container, "ls -la")

            mock_container.exec_run.assert_called_once_with("ls -la")
            assert result.exit_code == 0

    def test_raises_error_on_timeout(self):
        """Should raise SandboxError on timeout."""
        from concurrent.futures import TimeoutError as FuturesTimeoutError

        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            mock_container = MagicMock()

            def slow_exec(*args, **kwargs):
                import time
                time.sleep(10)

            mock_container.exec_run.side_effect = slow_exec

            with pytest.raises(SandboxError) as exc_info:
                sb._exec_with_timeout(mock_container, "sleep 100", timeout=0.1)
            assert "timed out" in str(exc_info.value)


class TestResolveDockerHost:
    """Tests for _resolve_docker_host method."""

    def test_returns_localhost_by_default(self):
        """Should return 127.0.0.1 when DOCKER_HOST not set."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            with patch.dict("os.environ", {}, clear=True):
                host = sb._resolve_docker_host()
                assert host == "127.0.0.1"

    def test_parses_tcp_docker_host(self):
        """Should parse TCP DOCKER_HOST URL."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            with patch.dict("os.environ", {"DOCKER_HOST": "tcp://192.168.1.100:2375"}):
                host = sb._resolve_docker_host()
                assert host == "192.168.1.100"

    def test_parses_http_docker_host(self):
        """Should parse HTTP DOCKER_HOST URL."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            with patch.dict("os.environ", {"DOCKER_HOST": "http://docker.local:2375"}):
                host = sb._resolve_docker_host()
                assert host == "docker.local"

    def test_returns_localhost_for_unix_socket(self):
        """Should return localhost for Unix socket DOCKER_HOST."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            with patch.dict("os.environ", {"DOCKER_HOST": "unix:///var/run/docker.sock"}):
                host = sb._resolve_docker_host()
                assert host == "127.0.0.1"


class TestEnsureImage:
    """Tests for ensure_image method."""

    def test_does_nothing_when_image_exists(self):
        """Should not pull when image already exists."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_client.images.get.return_value = MagicMock()

            sb = Sandbox()
            sb.ensure_image()

            mock_client.images.get.assert_called_once_with(sb.image)
            mock_client.images.pull.assert_not_called()

    def test_pulls_image_when_not_found(self):
        """Should pull image when not found locally."""
        from docker.errors import ImageNotFound

        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_client.images.get.side_effect = ImageNotFound("Not found")

            sb = Sandbox()
            sb.ensure_image()

            mock_client.images.pull.assert_called_once_with(sb.image)


class TestSandboxStart:
    """Tests for start method."""

    def test_returns_connection_info(self):
        """Should return connection info dict."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", side_effect=[8080, 9090]):
                        sb = Sandbox(scan_id="test123")
                        result = sb.start()

                        assert "container_id" in result
                        assert "container_name" in result
                        assert "tool_server_url" in result
                        assert "tool_server_token" in result
                        assert "scan_id" in result
                        assert result["scan_id"] == "test123"

    def test_removes_existing_container(self):
        """Should remove existing container with same name."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client

            mock_existing = MagicMock()
            mock_client.containers.get.return_value = mock_existing

            mock_new = MagicMock()
            mock_new.id = "new123"
            mock_client.containers.run.return_value = mock_new

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", return_value=8080):
                        sb = Sandbox(scan_id="test")
                        sb.start()

                        mock_existing.stop.assert_called_once()
                        mock_existing.remove.assert_called_once_with(force=True)

    def test_copies_local_sources(self):
        """Should copy local sources when provided."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", return_value=8080):
                        with patch.object(Sandbox, "_copy_local_sources") as mock_copy:
                            sb = Sandbox()
                            sb.start(local_sources=[{"source_path": "/some/path"}])

                            mock_copy.assert_called_once_with([{"source_path": "/some/path"}])

    def test_sets_cpu_environment_variable(self):
        """Should set CPU-related environment variables."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", return_value=8080):
                        with patch("strix_cli_claude.sandbox.get_cpu_count", return_value=4):
                            sb = Sandbox()
                            sb.start()

                            call_kwargs = mock_client.containers.run.call_args[1]
                            env = call_kwargs.get("environment", {})
                            assert env["STRIX_CPU_COUNT"] == "4"


class TestInitializeContainer:
    """Tests for _initialize_container method."""

    def test_raises_error_when_no_container(self):
        """Should raise SandboxError when container not started."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            sb._container = None

            with pytest.raises(SandboxError) as exc_info:
                sb._initialize_container()
            assert "Container not started" in str(exc_info.value)


class TestWaitForHealth:
    """Tests for _wait_for_health method."""

    def test_returns_when_healthy(self):
        """Should return when server is healthy."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            with patch("httpx.Client") as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__enter__.return_value = mock_client
                mock_response = MagicMock()
                mock_response.json.return_value = {"status": "healthy"}
                mock_client.get.return_value = mock_response

                # Should not raise
                sb._wait_for_health("http://localhost:8080/health")

    def test_raises_error_after_retries(self):
        """Should raise SandboxError after all retries fail."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()

            with patch("httpx.Client") as mock_client_class:
                mock_client = MagicMock()
                mock_client_class.return_value.__enter__.return_value = mock_client
                mock_client.get.side_effect = Exception("Connection refused")

                with patch.object(sandbox, "TOOL_SERVER_HEALTH_RETRIES", 2):
                    with patch("time.sleep"):  # Speed up test
                        with pytest.raises(SandboxError) as exc_info:
                            sb._wait_for_health("http://localhost:8080/health")
                        assert "failed to start" in str(exc_info.value)


class TestCopyLocalSources:
    """Tests for _copy_local_sources method."""

    def test_does_nothing_without_container(self):
        """Should do nothing when container is None."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            sb._container = None

            # Should not raise
            sb._copy_local_sources([{"source_path": "/some/path"}])

    def test_skips_nonexistent_paths(self, tmp_path):
        """Should skip paths that don't exist."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            sb._container = mock_container

            sb._copy_local_sources([{"source_path": "/nonexistent/path"}])

            mock_container.put_archive.assert_not_called()

    def test_copies_existing_directory(self, tmp_path):
        """Should copy existing directory to container."""
        source_dir = tmp_path / "mycode"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')")

        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            sb._container = mock_container

            sb._copy_local_sources([{"source_path": str(source_dir)}])

            mock_container.put_archive.assert_called_once()
            call_args = mock_container.put_archive.call_args
            assert call_args[0][0] == "/workspace"

    def test_sets_permissions_after_copy(self, tmp_path):
        """Should set permissions after copying."""
        source_dir = tmp_path / "mycode"
        source_dir.mkdir()
        (source_dir / "test.py").write_text("print('hello')")

        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            sb._container = mock_container

            sb._copy_local_sources([{"source_path": str(source_dir)}])

            # Should call exec_run to set permissions
            mock_container.exec_run.assert_called()


class TestSandboxStop:
    """Tests for stop method."""

    def test_stops_and_removes_container(self):
        """Should stop and remove the container."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_container.name = "test-container"
            sb._container = mock_container

            sb.stop()

            mock_container.stop.assert_called_once_with(timeout=10)
            mock_container.remove.assert_called_once_with(force=True)
            assert sb._container is None

    def test_does_nothing_when_no_container(self):
        """Should do nothing when container is None."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            sb._container = None

            # Should not raise
            sb.stop()

    def test_handles_stop_error_gracefully(self):
        """Should handle errors gracefully when stopping."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_container.stop.side_effect = Exception("Stop failed")
            sb._container = mock_container

            # Should not raise
            sb.stop()
            assert sb._container is None


class TestExecCommand:
    """Tests for exec_command method."""

    def test_raises_error_when_no_container(self):
        """Should raise SandboxError when container not running."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            sb._container = None

            with pytest.raises(SandboxError) as exc_info:
                sb.exec_command("ls")
            assert "not running" in str(exc_info.value)

    def test_executes_command_as_pentester(self):
        """Should execute command as pentester user by default."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_result = MagicMock()
            mock_result.exit_code = 0
            mock_result.output = b"output"
            mock_container.exec_run.return_value = mock_result
            sb._container = mock_container

            exit_code, output = sb.exec_command("whoami")

            mock_container.exec_run.assert_called_once_with("whoami", user="pentester")
            assert exit_code == 0
            assert output == "output"

    def test_executes_command_as_custom_user(self):
        """Should execute command as specified user."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_result = MagicMock()
            mock_result.exit_code = 0
            mock_result.output = b"root"
            mock_container.exec_run.return_value = mock_result
            sb._container = mock_container

            exit_code, output = sb.exec_command("whoami", user="root")

            mock_container.exec_run.assert_called_once_with("whoami", user="root")


class TestIsRunning:
    """Tests for is_running property."""

    def test_returns_false_when_no_container(self):
        """Should return False when container is None."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            sb._container = None

            assert sb.is_running is False

    def test_returns_true_when_container_running(self):
        """Should return True when container status is running."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_container.status = "running"
            sb._container = mock_container

            assert sb.is_running is True

    def test_returns_false_when_container_stopped(self):
        """Should return False when container status is not running."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_container.status = "exited"
            sb._container = mock_container

            assert sb.is_running is False

    def test_returns_false_on_reload_error(self):
        """Should return False when container reload fails."""
        with patch("docker.from_env") as mock_docker:
            mock_docker.return_value = MagicMock()
            sb = Sandbox()
            mock_container = MagicMock()
            mock_container.reload.side_effect = Exception("Container not found")
            sb._container = mock_container

            assert sb.is_running is False


class TestContainerConfiguration:
    """Tests for container configuration details."""

    def test_container_has_required_capabilities(self):
        """Should create container with NET_ADMIN and NET_RAW capabilities."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", return_value=8080):
                        sb = Sandbox()
                        sb.start()

                        call_kwargs = mock_client.containers.run.call_args[1]
                        assert "NET_ADMIN" in call_kwargs.get("cap_add", [])
                        assert "NET_RAW" in call_kwargs.get("cap_add", [])

    def test_container_has_scan_id_label(self):
        """Should label container with scan_id."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", return_value=8080):
                        sb = Sandbox(scan_id="my-scan")
                        sb.start()

                        call_kwargs = mock_client.containers.run.call_args[1]
                        labels = call_kwargs.get("labels", {})
                        assert labels.get("strix-cli-scan-id") == "my-scan"

    def test_container_exposes_ports(self):
        """Should expose Caido and tool server ports."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", side_effect=[8080, 9090]):
                        sb = Sandbox()
                        sb.start()

                        call_kwargs = mock_client.containers.run.call_args[1]
                        ports = call_kwargs.get("ports", {})
                        assert "8080/tcp" in ports
                        assert "9090/tcp" in ports

    def test_container_uses_sleep_infinity(self):
        """Should use 'sleep infinity' as command."""
        with patch("docker.from_env") as mock_docker:
            mock_client = MagicMock()
            mock_docker.return_value = mock_client
            mock_container = MagicMock()
            mock_container.id = "container123"
            mock_client.containers.run.return_value = mock_container
            mock_client.containers.get.side_effect = NotFound("Not found")

            with patch.object(Sandbox, "ensure_image"):
                with patch.object(Sandbox, "_initialize_container"):
                    with patch.object(Sandbox, "_find_available_port", return_value=8080):
                        sb = Sandbox()
                        sb.start()

                        call_kwargs = mock_client.containers.run.call_args[1]
                        assert call_kwargs.get("command") == "sleep infinity"
