external_url 'https://gitlab.ahlooii.com'
 gitlab_rails['gitlab_shell_ssh_port'] = 2278
registry_external_url 'https://registry.ahlooii.com:5005'
gitlab_rails['registry_enabled'] = true
gitlab_rails['registry_host'] = "registry.ahlooii.com"
gitlab_rails['registry_port'] = "5005"
gitlab_rails['registry_path'] = "/var/opt/gitlab/gitlab-rails/shared/registry"
gitlab_rails['registry_api_url'] = "http://127.0.0.1:5000"
gitlab_rails['registry_key_path'] = "/var/opt/gitlab/gitlab-rails/etc/gitlab-registry.key"
registry['enable'] = true
registry['token_realm'] = "https://gitlab.ahlooii.com:443"
registry['registry_http_addr'] = "localhost:5000"
registry['log_directory'] = "/var/log/gitlab/registry"
registry['env_directory'] = "/opt/gitlab/etc/registry/env"
registry['env'] = {
  'SSL_CERT_DIR' => "/opt/gitlab/embedded/ssl/certs/"
}
registry['rootcertbundle'] = "/var/opt/gitlab/registry/gitlab-registry.crt"
puma['worker_processes'] = 0
 sidekiq['concurrency'] = 10
registry_nginx['enable'] = true
registry_nginx['redirect_http_to_https'] = true
registry_nginx['listen_port'] = 5005
registry_nginx['ssl_certificate'] = "/etc/gitlab/ssl/registry.ahlooii.com/certificate.pem"
registry_nginx['ssl_certificate_key'] = "/etc/gitlab/ssl/registry.ahlooii.com/certificate.key"
gitaly['configuration'] = {
  cgroups: {
    mountpoint: '/sys/fs/cgroup',
    hierarchy_root: 'gitaly',
    memory_bytes: 500000,
  },
  concurrency: [
    {
      rpc: '/gitaly.SmartHTTPService/PostReceivePack',
      max_per_repo: 3
    }, {
      rpc: '/gitaly.SSHService/SSHUploadPack',
      max_per_repo: 3
    }
  ],
}
