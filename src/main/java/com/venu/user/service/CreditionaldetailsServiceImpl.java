package com.venu.user.service;

import com.venu.user.model.Creditional;
import com.venu.user.model.CreditionalDetailsImpl;
import com.venu.user.repository.CreditionalRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CreditionaldetailsServiceImpl implements CreditionalDetailsService {
  @Autowired CreditionalRepository creditionalRepository;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Creditional creditional =
        creditionalRepository
            .findByUsername(username)
            .orElseThrow(
                () -> new UsernameNotFoundException("User Not Found with username: " + username));

    return CreditionalDetailsImpl.build(creditional);
  }
}
