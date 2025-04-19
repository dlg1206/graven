"""
File: __main__.py

Description: Read all cve's ID and searches up the matching CWE's and instert CWE info into the breadcrumbs datatbase

"""
import asyncio
import os

import mysql.connector
from dotenv import load_dotenv

from cwe_bd_push import write_cwe_to_db
from cwe_db_pull import read_cwe_from_db
from cwe_site_pull import process_cwes
from parse_xwe_xml import parse_cwe_xml

async def main():
    load_dotenv()  # collects YOUR .env info to access that database

    try:
        # connects to the database
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST"),
            user=os.getenv("MYSQL_USER"),
            password=os.getenv("MYSQL_PASSWORD"),
            database=os.getenv("MYSQL_DATABASE"),
            port=int(os.getenv("EXTERNAL_PORT"))
        )
        cursor = conn.cursor()

        # grab list of cwe ids to search with
        cwe_id_list = read_cwe_from_db(cursor)


        # Parse the XML file and retrieve a list of CWE IDs.
        xml_cwe_list = parse_cwe_xml()

        # for each ID in mitre_cwe_id_list & cwe_id_list add to new list
        while cwe_id_list:
            cwe_id_num = cwe_id_list.pop()
            if cwe_id_num not in xml_cwe_list:
                print(f"ID: CWE-{cwe_id_num} is not in the MITRE DB (xml)")   # print output


        # call a methods that take a list of cve  and return a list of cwe objects
        # todo - uncomment to insert to db, should be seperate method / command
        # cwe_data_list = await process_cwes(cwe_id_list)
        #
        # # Check if the cwe is already in the database
        # for cwe_obj in cwe_data_list:
        #     write_cwe_to_db(conn, cwe_obj)

        # conn.commit()
        # print("Insert Successful")
    except mysql.connector.Error as err:
        print(f"Error occurred: {err}")
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    asyncio.run(main())
