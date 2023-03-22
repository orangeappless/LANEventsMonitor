import configparser


def get_action_levels():
    # Get threat levels of each action from config file
    config = configparser.ConfigParser()
    config.read('config.ini')
    config_items = dict(config.items('THREAT_MGMT'))

    return config_items


def get_current_level(threat_file):
    with open(f'utilities/{threat_file}') as file:
        current_threat = int(file.read())

    return current_threat


def update_threat(action, threat_file, iters=1):
    action_threat_level = get_action_levels()
    print(action_threat_level)

    with open(f'utilities/{threat_file}', 'r+') as file:
        # Read current threat level
        current_threat = int(file.read())
        
        # Write updated threat level
        file.seek(0)
        current_threat += int((int(action_threat_level[action]) * iters))
        updated_threat = max(0, current_threat)
        file.write(str(updated_threat) + '\n')
        file.truncate()
