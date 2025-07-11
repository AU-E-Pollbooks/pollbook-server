# E-Pollbook Ansible Automation

This repository (`pollbook-ansible/`) contains all the necessary scripts, templates, and playbooks to **automate the deployment and configuration of the E-Pollbook system using Docker and Ansible**.

Note: The network used in this project is 172.16.0.0, and it is configured accordingly in the Docker Compose file. Ensure you update the configuration as needed for your environment, particularly for IP addresses and network configurations.

---

## Directory Structure

e-pollbook-ansible/

├── README.md # ← You are here!

├── host_vars/ # Node-specific configuration variables (YAML)

├── output/ # Rendered config files (auto-generated)

├── playbooks/ # Main Ansible playbooks (deploy, render_and_copy_configs, etc.)

├── templates/ # Jinja2 templates for all config files

---

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Ansible](https://docs.ansible.com/)
- Python 3.x

Install Ansible (if not already):

    pip install ansible


# Workflow Overview:

1. Edit node configurations in host_vars/checkin_server.yml, host_vars/id_server.yml, host_vars/client1.yml, ..., host_vars/client4.yml.

2. Render and copy configs: Use Ansible to generate all config files per container (check-in server, ID server, and clients) and copy them into the appropriate Docker containers.

3. Deploy containers: If not already running, use the main deploy playbook to start the containers.


# How to Use:

    1. Clone the Repo
        
        git clone <your-private-git-url>
        
        cd pollbook/pollbook-ansible

    2. Initial Deployment (First Time Only)

        This will build and start all Docker containers, generate initial configs, and set up everything.

        Deploy and start everything. Run the full_deploy.yml playbook to deploy the whole project in your system:
            
            ansible-playbook full_deploy.yml


        This will:

            1. Clean up existing containers/networks

            2. Build Docker images and start all containers

            3. Perform any initial key/cert generation

            4. Wait for containers to be healthy

    
    3. Change Configuration (Anytime Later)
        
        Whenever you want to update the configuration file for any node (Check-in Server, ID Server, or Clients):

        Edit the corresponding file in host_vars/
    
        For example:

            vim host_vars/client1.yml

        Render and copy updated configs (no need to restart containers):

            ansible-playbook render_and_copy_configs.yml


            This will:

                1. Render all templates for every container using the updated YAML files

                2. Copy the new configs into the correct running containers instantly




# Notes

1. All rendered config files are placed in the output/ directory.

2. Make sure Docker and Docker Compose are running before running the playbooks.

3. For advanced customization, edit the Jinja2 templates in templates/ and the playbooks in ansible-configs/.

4. The containers' names are defined in the playbook and need to match the ones running in Docker. Always ensure they are correct in the docker ps command output before running playbooks.

5. Use docker-compose down if you need to clean up containers before re-deploying.


