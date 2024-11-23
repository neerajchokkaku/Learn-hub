import React from 'react';
import * as FaIcons from 'react-icons/fa';
import * as AiIcons from 'react-icons/ai';
import * as IoIcons from 'react-icons/io';
import * as RiIcons from 'react-icons/ri';

export const SidebarData = [
  {
    title: 'Home',
    path: '/Dashboard',
    icon: <AiIcons.AiFillHome />,
    iconClosed: <RiIcons.RiArrowDownSFill />,
    iconOpened: <RiIcons.RiArrowUpSFill />,

   
  },
  {
    title: 'ViewCourses',
    path: '/view-courses',
    icon: <IoIcons.IoIosPaper />,
    iconClosed: <RiIcons.RiArrowDownSFill />,
    iconOpened: <RiIcons.RiArrowUpSFill />,

   
      
  },
  {
    title: 'Registered Courses',
    path: '/my-courses',
    icon: <FaIcons.FaCartPlus />
  },
  {
    title: 'My courses',
    path: '/paid-course',
    icon: <IoIcons.IoMdPeople />
  },
 
  {
    title: 'Support',
    path: '/support-form',
    icon: <IoIcons.IoMdHelpCircle />
  },
  {
    title: 'Answers',
    path: '/Answer',
    icon: <IoIcons.IoMdHelpCircle />
  }
];