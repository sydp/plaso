# -*- coding: utf-8 -*-
"""Parser for Android bugreports.

This parser currently only parses data from the "DUMP OF SERVICE dbinfo"
section, specifically the "Most recently executed operations" and
"Database files in <path>".

"""

from dfdatetime import time_elements as dfdatetime_time_elements

import pyparsing

from plaso.containers import events
from plaso.containers import time_events

from plaso.lib import definitions
from plaso.lib import errors

from plaso.parsers import manager
from plaso.parsers import text_parser


class AndroidDBInfoStatEventData(events.EventData):
  """Android DBInfo Stat Event Data.

  Attributes:
    name (str): the name of the database file
    path (str): the path to the database file
    size (str): the reported file size (in bytes)
  """

  DATA_TYPE = 'android:dbinfo:stat'

  def __init__(self):
    """Initializes event data."""
    super(AndroidDBInfoStatEventData, self).__init__(data_type=self.DATA_TYPE)
    self.name = None
    self.path = None
    self.size = None


class AndroidMostRecentlyExecutedEventData(events.EventData):
  """Android DBInfo Most Recently Executed Event Data.

  Attributes:
    message (str): the status message
    path (str): the database path
    sql_statement (str): the sql statement
  """

  DATA_TYPE = 'android:dbinfo:mre'

  def __init__(self):
    """Initializes Android DBInfo MRE event data."""
    super(AndroidMostRecentlyExecutedEventData, self).__init__(
        data_type=self.DATA_TYPE)
    self.message = None
    self.path = None
    self.sql_statement = None


class AndroidBugreportParser(text_parser.PyparsingMultiLineTextParser):
  """Parser for Android Bugreport files."""

  NAME = 'android_bugreport'
  DATA_FORMAT = 'Android Bugreport'

  BUFFER_SIZE = 8092

  MAXIMUM_CONSECUTIVE_LINE_FAILURES = 100000

  DATE_TIME_MSEC = text_parser.PyparsingConstants.DATE_TIME_MSEC
  DATE_TIME = (text_parser.PyparsingConstants.DATE_ELEMENTS + 
               'T' + text_parser.PyparsingConstants.TIME_ELEMENTS)

  _ENCODING = 'utf-8'

  _MOST_RECENTLY_EXECUTED_OPERATIONS = (
      pyparsing.Optional(pyparsing.White().suppress()) +
      pyparsing.Suppress('Most recently executed operations:') +
      pyparsing.ZeroOrMore(
          pyparsing.Group(
              pyparsing.Word(pyparsing.nums) +
              pyparsing.Suppress(':') +
              pyparsing.Suppress('[') +
              DATE_TIME_MSEC.setResultsName('date_time_msec') +
              pyparsing.Suppress(']') +
              pyparsing.Group(
                  pyparsing.Word(pyparsing.alphas) +
                  pyparsing.Literal('took') +
                  pyparsing.Word(pyparsing.nums) +
                  pyparsing.Literal('ms') +
                  pyparsing.Literal('-') +
                  pyparsing.Word(pyparsing.alphas)).setResultsName('message') +
              pyparsing.Suppress(',') +
              pyparsing.Suppress('sql=') +
              pyparsing.QuotedString('"').setResultsName('sql_statement') +
              pyparsing.Suppress(',') +
              pyparsing.Suppress('path=') +
              pyparsing.restOfLine.setResultsName('path')).setResultsName('db_operation*')))

  _DATABASE_FILES_STAT = (
      pyparsing.Optional(pyparsing.Suppress(pyparsing.White())) +
      pyparsing.Suppress('Database files in ') +
      pyparsing.restOfLine.setResultsName('path') +
      pyparsing.OneOrMore(
          pyparsing.Group(
              pyparsing.Word(pyparsing.printables).setResultsName('name') +
              pyparsing.Word(pyparsing.nums).setResultsName('size') +
              pyparsing.Word(
                  pyparsing.alphas, exact=1).setResultsName('unit') +
              pyparsing.Suppress('ctime=') +
              pyparsing.Combine(
                  DATE_TIME +
                  pyparsing.Literal('Z')).setResultsName('creation_time') +
              pyparsing.Suppress('mtime=') +
              pyparsing.Combine(
                  DATE_TIME +
                  pyparsing.Literal('Z')).setResultsName('modification_time') +
              pyparsing.Suppress('atime=') +
              pyparsing.Combine(
                  DATE_TIME +
                  pyparsing.Literal('Z')).setResultsName('access_time')
          ).setResultsName('file_info*')
      )
  )

  LINE_STRUCTURES = [
      ('dbinfo_mre', _MOST_RECENTLY_EXECUTED_OPERATIONS),
      ('dbinfo_stat', _DATABASE_FILES_STAT)
  ]

  _SUPPORTED_KEYS = frozenset([key for key, _ in LINE_STRUCTURES])

  def _ParseDateTimeMicroSeconds(self, structure):
    """Parses a DATE_TIME_MSEC data structure to a TimeElementsInMicroseconds
       object.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      structure (pyparsing.ParseResults): structure of tokens derived from
          a line of a text file.

    Returns:
      dfdatetime.TimeElementsInMicroseconds: parsed datetime
    """
    return dfdatetime_time_elements.TimeElementsInMicroseconds(
        time_elements_tuple=(
            self._GetValueFromStructure(structure, 'year'),
            self._GetValueFromStructure(structure, 'month'),
            self._GetValueFromStructure(structure, 'day_of_month'),
            self._GetValueFromStructure(structure, 'hours'),
            self._GetValueFromStructure(structure, 'minutes'),
            self._GetValueFromStructure(structure, 'seconds'),
            self._GetValueFromStructure(structure, 'microseconds')))

  def _ParseDateTimeSeconds(self, structure):
    """Parses a DATE_TIME_MSEC data structure to a TimeElementsInSeconds
      object.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      structure (pyparsing.ParseResults): structure of tokens derived from
          a line of a text file.

    Returns:
      dfdatetime.TimeElementsInMicroseconds: parsed datetime
    """
    return dfdatetime_time_elements.TimeElements(
        time_elements_tuple=(
            self._GetValueFromStructure(structure, 'year'),
            self._GetValueFromStructure(structure, 'month'),
            self._GetValueFromStructure(structure, 'day_of_month'),
            self._GetValueFromStructure(structure, 'hours'),
            self._GetValueFromStructure(structure, 'minutes'),
            self._GetValueFromStructure(structure, 'seconds')))

  def _ParseDbInfoMREStructure(self, parser_mediator, structure):
    """Parse a dumpsys dbInfo 'Most Recently Executed' structure"""
    for db_structure in structure.get('db_operation', []):
      print(db_structure)
      message = self._GetValueFromStructure(db_structure, 'message')
      path = self._GetValueFromStructure(db_structure, 'path')
      sql_statement = self._GetValueFromStructure(db_structure, 'sql_statement')
      event_data = AndroidMostRecentlyExecutedEventData()
      event_data.mesesage = message
      event_data.path = path
      event_data.sql_statement = sql_statement

      # TODO assume this is in localtime.
      date_time_structure = self._GetValueFromStructure(db_structure, 'date_time_msec')
      event_date_time = self._ParseDateTimeMicroSeconds(date_time_structure)
      event = time_events.DateTimeValuesEvent(
          event_date_time, definitions.TIME_DESCRIPTION_RECORDED)
      parser_mediator.ProduceEventWithEventData(event, event_data)

  def _ParseDbInfoFileStatStructure(self, parser_mediator, structure):
    """Parse a dumpsys dbInfo 'file stat' line"""

    file_path = self._GetValueFromStructure(structure, 'path')
    file_infos = self._GetValueFromStructure(structure, 'file_info', [])

    for file_info in file_infos:
      file_name = self._GetValueFromStructure(file_info,'name')
      file_size = self._GetValueFromStructure(file_info, 'size')

      event_data = AndroidDBInfoStatEventData()
      event_data.name = file_name
      event_data.path = file_path
      event_data.size = file_size

      creation_time = self._GetValueFromStructure(file_info, 'creation_time')
      if creation_time:
        event_date_time = self._ParseDateTimeSeconds(creation_time)
        event = time_events.DateTimeValuesEvent(
            event_date_time, definitions.TIME_DESCRIPTION_CREATION)
        parser_mediator.ProduceEventWithEventData(event, event_data)

      modification_time = self._GetValueFromStructure(
          file_info, 'modification_time')
      if modification_time:
        event_date_time = self._ParseDateTimeSeconds(modification_time)
        event = time_events.DateTimeValuesEvent(
            event_date_time, definitions.TIME_DESCRIPTION_MODIFICATION)
        parser_mediator.ProduceEventWithEventData(event, event_data)

      access_time = self._GetValueFromStructure(file_info, 'access_time')
      if access_time:
        event_date_time = self._ParseDateTimeSeconds(access_time)
        event = time_events.DateTimeValuesEvent(
            event_date_time, definitions.TIME_DESCRIPTION_LAST_ACCESS)
        parser_mediator.ProduceEventWithEventData(event, event_data)

  def ParseRecord(self, parser_mediator, key, structure):
    """Parse the record and create EventData objects.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      key (str): name of the parsed structure.
      structure (pyparsing.ParseResults): structure of tokens derived from
          a line of a text file.

    Raises:
      ParseError: when the structure type is unknown.
    """
    if key not in self._SUPPORTED_KEYS:
      raise errors.ParseError(
          'Unable to parse record, unknown structure: {0:s}'.foramt(key))
    
    if key == 'dbinfo_stat':
      self._ParseDbInfoFileStatStructure(parser_mediator, structure)
    elif key == 'dbinfo_mre':
      self._ParseDbInfoMREStructure(parser_mediator, structure)
    #elif key in ('threadtime_line', 'time_line'):
    #  self._ParseLogcatLine(parser_mediator, structure)


  def VerifyStructure(self, parser_mediator, lines):
    """Verifies whether the content corresponds to an Android bugreport.

    This function should read enough text from the text file to confirm
    that the file is the correct one for this particular parser.

    Args:
      parser_mediator (ParserMediator): mediates interactions between parsers
          and other components, such as storage and dfvfs.
      lines (str): one or more lines from the text file.

    Returns:
      bool: True if this is the correct parser, False otherwise.
    """
    header_lines = lines.split('\n')

    if len(header_lines) < 3:
      return False

    if header_lines[0] != '========================================================':
      return False

    if not header_lines[1].startswith('== dumpstate: '):
      return False

    if header_lines[2] != '========================================================':
      return False

    return True


manager.ParsersManager.RegisterParser(AndroidBugreportParser)
