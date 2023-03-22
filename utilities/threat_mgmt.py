import configparser


def get_threat_level(threat_file):
    with open(f'utilities/{threat_file}') as file:
        current_threat = int(file.read())

    return current_threat


def update_threat(action, threat_file, iters=1):
    # Get threat levels from config file
    config = configparser.ConfigParser()
    config.read('config.ini')
    config_items = dict(config.items('THREAT_MGMT'))

    threat_levels = {
        'dir_modification': int(config_items['dir_modification']),
        'failed_ssh': int(config_items['failed_ssh']),
        'success_ssh': int(config_items['success_ssh']),
        'clear_ssh': int(config_items['clear_ssh'])
    }

    with open(f'utilities/{threat_file}', 'r+') as file:
        # Read current threat level
        current_threat = int(file.read())
        
        # Write updated threat level
        file.seek(0)
        current_threat += (threat_levels[action] * iters)
        updated_threat = max(0, current_threat)
        file.write(str(updated_threat) + '\n')
        file.truncate()
