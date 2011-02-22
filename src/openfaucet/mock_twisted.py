# Copyright 2011 Midokura KK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Mock implementations of Twisted interfaces.

import collections

import twisted.internet.error


class MockDelayedCall(object):
  """A mock implementation of the IDelayedCall interface.
  """

  __slots__ = ('reactor_time', 'time', 'already_cancelled',
               'already_called', 'callable', 'args', 'kw')

  def __init__(self, **kwargs):
    for k, v in kwargs.iteritems():
      setattr(self, k, v)

  def getTime(self):
    """Get time when delayed call will happen.

    Returns:
      Time in seconds since epoch (a float).
    """
    return self.time

  def cancel(self):
    """Cancel the scheduled call.

    Raises:
      twisted.internet.error.AlreadyCalled if the call has already happened.
      twisted.internet.error.AlreadyCancelled if the call has already been
          cancelled.
    """
    if self.already_cancelled:
      raise twisted.internet.error.AlreadyCancelled()
    if self.already_called:
      raise twisted.internet.error.AlreadyCalled()
    self.already_cancelled = True
    self.reactor_time.delayed_calls.remove(self)

  def delay(self, secondsLater):
    """Delay the scheduled call.

    Args:

      secondsLater: How many seconds from its current firing time to
          delay.

    Raises:
      twisted.internet.error.AlreadyCalled if the call has already happened.
      twisted.internet.error.AlreadyCancelled if the call has already been
          cancelled.
    """
    if self.already_cancelled:
      raise twisted.internet.error.AlreadyCancelled()
    if self.already_called:
      raise twisted.internet.error.AlreadyCalled()
    self.time += secondsLater

  def reset(self, secondsFromNow):
    """Reset the scheduled call's timer.

    Args:
      secondsFromNow: How many seconds from now it should fire,
          equivalent to .cancel() and then doing another
          reactor.callLater(secondsLater, ...).
      
    Raises:
      twisted.internet.error.AlreadyCalled if the call has already happened.
      twisted.internet.error.AlreadyCancelled if the call has already been cancelled. 
    """
    if self.already_cancelled:
      raise twisted.internet.error.AlreadyCancelled()
    if self.already_called:
      raise twisted.internet.error.AlreadyCalled()
    self.time = self.reactor_time.seconds() + secondsFromNow

  def active(self):
    """Test if the scheduled call is still active.

    Returns:
      True if this call is still active, False if it has been called
      or cancelled.
    """
    return not self.already_cancelled and not self.already_called

  def __repr__(self):
    return '%s(**%s)' % (self.__class__.__name__,
                         dict((k, getattr(self, k)) for k in self.__slots__))

  def __cmp__(self, other):
    for k in self.__slots__:
      if getattr(self, k) < getattr(other, k):
        return -1
      elif getattr(self, k) > getattr(other, k):
        return 1
    return 0


class MockReactorTime(object):
  """A mock implementation of the IReactorTime interface.

  This client has an internal clock, as a counter of seconds since
  January 1, 1970, that is initially set to zero.  This clock must be
  explicitly incremented by clients, by calling increment_time(), to
  simulate the passing of time in the Memcached server.  Calling
  increment_time() triggers delayed calls whose triggering times are
  lower or equal to the new clock value.
  """

  __slots__ = ('delayed_calls', 'time')

  def __init__(self):
    """Initialize this IReactorTime.
    """
    self.delayed_calls = []
    self.time = 0.0

  def seconds(self):
    """Get the current time in seconds.

    Returns:
      A number-like object of some sort.
    """
    return self.time

  def callLater(self, delay, callable, *args, **kw):
    """Call a function later.

    Args:
      delay: The number of seconds to wait, as a float.
      callable: The callable object to call later.
      args: The arguments to call it with.
      kw: The keyword arguments to call it with.

    Returns:
      An object which provides IDelayedCall and can be used to cancel
      the scheduled call, by calling its cancel() method. It also may
      be rescheduled by calling its delay() or reset() methods.
    """
    delayed_call = MockDelayedCall(
        reactor_time=self, time=self.time+delay, already_cancelled=False,
        already_called=False, callable=callable, args=args, kw=kw)
    self.delayed_calls.append(delayed_call)
    return delayed_call

  def getDelayedCalls(self):
    """Retrieve all currently scheduled delayed calls.

    Returns:
      A tuple of all IDelayedCall providers representing all currently
      scheduled calls. This is everything that has been returned by
      callLater but not yet called or canceled.
    """
    return tuple(self.delayed_calls)

  # Useful methods for testing.

  def increment_time(self, delta):
    """Increment the clock counter.

    All delayed calls with calling times lower or equal to the new
    clock value are called.

    Args:
      delta: The number of seconds to add to the clock.
    """
    self.time += delta

    active_delayed_calls = []
    for delayed_call in self.delayed_calls:
      if delayed_call.active():
        if delayed_call.getTime() <= self.time:
          delayed_call.already_called = True
          delayed_call.callable(*delayed_call.args, **delayed_call.kw)
        else:
          active_delayed_calls.append(delayed_call)
    self.delayed_calls = active_delayed_calls
