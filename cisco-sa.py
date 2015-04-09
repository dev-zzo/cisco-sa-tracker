'''Cisco Security Advisory processing script

What it does:
* Go through all the products listed as affected
* Format these into a list
* Fetch the latest version of such list from github repo
* Verify if there are any differences
* If there are, push an updated version to the repo

What it does not:
* Handle older SA with a list instead of a table
* Process the referenced bugs

'''

from __future__ import print_function
import sys
import requests
import re
import pprint
import json
import argparse

def process_tabular(sa_body):
    '''Process the vulnerable products list (table form)'''
    junk, sep, sa_body = sa_body.partition('<tbody>')
    sa_body, sep, junk = sa_body.partition('</tbody>')
    if sep != '</tbody>':
        print('Could not find the ending tag for affected products list in SA text.')
        exit(4)

    # Unescape the stuff somewhat
    sa_body = sa_body.replace('&nbsp;', ' ')
    # Regexp hell: transform the text into something that can be handled by machine
    sa_body = re.sub(r'<br />[\r\n]*\s*', '<br>', sa_body)
    sa_body = re.sub(r' style="[^"]+"', '', sa_body)
    sa_body = re.sub(r'[\r\n]\s*', '', sa_body)
    sa_body = re.sub(r'</tr>', "</tr>\n", sa_body)


    lines = sa_body.splitlines()
    entries = []
    for line in lines:
        if line.startswith('<tr><th'):
            continue
        try:
            prod_name, bug_id, fixes = line[8:-10].split('</td><td>')
        except ValueError:
            print('Unexpected entry format detected:')
            print(repr(line))
            print('Input text dumped.')
            open('dump.txt', 'w').write(sa_body)
            exit(101)
        prod_name = str(prod_name.strip())
        bug_id = str(bug_id.strip()[-14:-4])
        if not re.match(r'CSC\w\w\d\d\d\d\d', bug_id):
            print('Whoops! Crappy bug ID spotted for product "%s"' % prod_name)
            bug_id = '!INVALID!'
        fixes = str(fixes).strip()
        if fixes:
            while fixes.endswith('<br>'):
                fixes = fixes[:-4].strip()
            fixes = fixes.split('<br>')
        else:
            fixes = None
        entry = [prod_name, bug_id, fixes]
        entries.append(entry)
    return entries

def process_sa(sa_url):
    '''Process the SA and return a diff-friendly text form'''
    # Get the SA
    print('Retrieving the SA text...')
    try:
        r = requests.get(sa_url)
        r.raise_for_status()
        sa_text = r.text
    except Exception, e:
        print('Something went wrong when fetching the Cisco SA.')
        print(e)
        exit(3)
        
    mo = re.search(r'<h2>Revision ([^<]*)</h2>', sa_text)
    if mo:
        revision = mo.group(1)
    else:
        revision = 'UNKNOWN'
    print('Revision: %s' % revision)

    # Partition the SA text to get only what we need
    junk, sep, sa_body = sa_text.partition('<a name="vps">')
    if sep != '<a name="vps">':
        print('Could not find the starting tag for affected products list in SA text.')
        exit(4)
    sa_body, sep, junk = sa_body.partition('<a name="nonvulnerable">')
    if sep != '<a name="nonvulnerable">':
        print('Could not find the starting tag for affected products list in SA text.')
        exit(4)

    # Verify the format...
    # Currently, it's either a table or a list
    if '<tbody>' in sa_body:
        print('Detected product list format: tabular')
        entries = process_tabular(sa_body)
    else:
        print('Could not detect the product list format.')
        print('Dumping the raw page.')
        open('dump.txt', 'w').write(sa_body)
        exit(5)
    text = pprint.pformat(entries, 2, 120)
    return { 'revision': revision, 'text': text }

GITHUB_API_BASE = 'https://api.github.com/repos/dev-zzo/cisco-sa-tracker'

def update_repo(data, username, password):
    # Ref: https://developer.github.com/v3/git/
    
    sa_id = data['id']
    text = data['text']
    # Get the latest commit id
    r = requests.get(GITHUB_API_BASE + '/git/refs/heads/master')
    r.raise_for_status()
    o = r.json()
    if not o['object'] or o['object']['type'] != 'commit':
        return False
    last_commit_sha = str(o['object']['sha'])
    print('Last master commit: %s' % last_commit_sha)
    # Get the tree ref for that commit
    r = requests.get(GITHUB_API_BASE + '/git/commits/' + last_commit_sha)
    r.raise_for_status()
    o = r.json()
    last_commit_tree = str(o['tree']['sha'])
    print('Last commit tree: %s' % last_commit_tree)
    # Retrieve the tree object
    r = requests.get(GITHUB_API_BASE + '/git/trees/' + last_commit_tree)
    r.raise_for_status()
    o = r.json()
    # Check if the file was in there previously
    for item in o['tree']:
        if item['path'] == sa_id:
            blob_sha = str(item['sha'])
            print('Last blob: %s' % blob_sha)
            # Check if the content is the same
            r = requests.get(GITHUB_API_BASE + '/git/blobs/' + blob_sha)
            r.raise_for_status()
            o = r.json()
            if o['size'] == len(text):
                print('Blob size matches.')
                content = str(o['content'])
                encoding = str(o['encoding'])
                print('Blob encoding: %s' % encoding)
                if encoding == 'base64':
                    import base64
                    content = base64.b64decode(content)
                elif encoding == 'utf-8':
                    pass
                else:
                    print('WARN: encoding unknown, will likely make an empty commit')
                if content == text:
                    print('No changes detected.')
                    return True
                print('Text changed.')
                open(sa_id + '.old.txt', 'w').write(content)
                open(sa_id + '.new.txt', 'w').write(text)
            else:
                print('Blob size differs.')
                # If the size is different -- no point in comparing textually
            break
    else:
        print('No previous version found.')
    # From here on, we'll need creds to update the repo.
    if not username or not password:
        print('Was about to update the repo, but you did not provide credentials to do so.')
        return False
    # Create a new blob with new content
    r = requests.post(GITHUB_API_BASE + '/git/blobs',
        headers={ 'content-type': 'application/json' },
        data=json.dumps({
            'content': text,
            'encoding': 'utf-8',
        }),
        auth=requests.auth.HTTPBasicAuth(username, password)
        )
    r.raise_for_status()
    o = r.json()
    new_blob_sha = str(o['sha'])
    print('Created new blob %s' % new_blob_sha)
    # Create a new tree with the new blob pointer
    r = requests.post(GITHUB_API_BASE + '/git/trees',
        headers={ 'content-type': 'application/json' },
        data=json.dumps({
            'base_tree': last_commit_tree,
            'tree': [{
                'path': sa_id,
                'mode': '100644',
                'type': 'blob',
                'sha': new_blob_sha,
            }]
        }),
        auth=requests.auth.HTTPBasicAuth(username, password)
        )
    r.raise_for_status()
    o = r.json()
    new_tree_sha = str(o['sha'])
    print('Created new tree %s' % new_tree_sha)
    # Create a new commit with the new tree pointer
    r = requests.post(GITHUB_API_BASE + '/git/commits',
        headers={ 'content-type': 'application/json' },
        data=json.dumps({
            'message': 'Updating %s (rev. %s)' % (sa_id, data['revision']),
            'tree': new_tree_sha,
            'parents': [last_commit_sha],
        }),
        auth=requests.auth.HTTPBasicAuth(username, password)
        )
    r.raise_for_status()
    o = r.json()
    new_commit_sha = str(o['sha'])
    print('Created new commit %s' % new_commit_sha)
    # Update the master branch
    r = requests.patch(GITHUB_API_BASE + '/git/refs/heads/master',
        headers={ 'content-type': 'application/json' },
        data=json.dumps({
            'sha': new_commit_sha,
        }),
        auth=requests.auth.HTTPBasicAuth(username, password)
        )
    r.raise_for_status()
    o = r.json()
    return True

def process_and_update(url, username, password):
    print()
    # Get the SA ID from the URL
    junk, sep, sa_id = url.rpartition('/')
    del junk
    if sep != '/':
        print('The URL seems incorrect.')
        exit(2)
    print('Cisco SA ID: %s' % (sa_id))

    data = process_sa(url)
    data['id'] = sa_id
    return update_repo(data, username, password)

def do_all(username, password):
    advisories = [
            'cisco-sa-20150408-ntpd',
            'cisco-sa-20150320-openssl',
            'cisco-sa-20150310-ssl',
            'cisco-sa-20150128-ghost',
            'cisco-sa-20141222-ntpd',
            'cisco-sa-20141015-poodle',
        ]
    for sa in advisories:
        process_and_update('http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/' + sa, username, password)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cisco SA Helper Script by dev_zzo')
    parser.add_argument('url',
        nargs='?',
        help='A Cisco advisory URL to process')
    parser.add_argument('--username',
        help='GitHub username to authenticate with')
    parser.add_argument('--password',
        help='GitHub password to authenticate with')
    args = parser.parse_args()

    if args.url is not None:
        process_and_update(args.url, args.username, args.password)
    else:
        do_all(args.username, args.password)
    print('Done!')
